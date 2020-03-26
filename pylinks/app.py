import base64
import datetime
import logging
import uuid
from typing import Dict, List, Union

import argon2  # type: ignore
import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from pylinks import config, crud, schemas
from pylinks.auth import BasicAuth, OAuth2PasswordBearerCookie, RequiresLoginException, create_access_token
from pylinks.constants import USER_ROLE_MAP, UserRole
from pylinks.database import SessionLocal, engine
from pylinks.models import Base

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

Base.metadata.create_all(bind=engine)

ph = argon2.PasswordHasher()
oauth2_scheme = OAuth2PasswordBearerCookie(tokenUrl="/token")
basic_auth = BasicAuth(auto_error=False)
app = FastAPI()
env = config.read_from_env()
KEY = env.key
DOMAIN = env.domain


@app.exception_handler(RequiresLoginException)
def exception_handler(request: Request, exc: RequiresLoginException) -> Response:
    return RedirectResponse(url="/login_basic")


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    try:
        ph.verify(hashed_password, plain_password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False


def get_current_user(token: str = Depends(oauth2_scheme)) -> int:
    credentials_exception = HTTPException(
        status_code=status.HTTP_403_FORBIDDEN, detail="Could not validate credentials"
    )
    try:
        payload = jwt.decode(token, KEY, algorithms=["HS256"])
        user_id: int = payload.get("sub")  # type: ignore
        if user_id is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    return user_id


@app.post("/jwt")
def create_jwt(auth: schemas.Login, db: Session = Depends(get_db)) -> str:
    user = crud.get_user_by_name(db, username=auth.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect username or password")

    if not verify_password(auth.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect Username or password")

    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(user.password)
        logger.info("Rehash Password for user:%s", user.username)
        db.commit()

    access_token = create_access_token(data={"sub": user.id}, key=KEY)
    token = jsonable_encoder(access_token)

    return f"Bearer {token}"


@app.post("/token", response_model=schemas.Token)
def route_login_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.get_user_by_name(db, username=form_data.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect username or password")

    if not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect Username or password")

    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(form_data.password)
        logger.info("Rehash Password for user:%s", user.username)
        db.commit()

    access_token = create_access_token(data={"sub": user.id}, key=KEY)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/logout")
def route_logout_and_remove_cookie():
    response = RedirectResponse(url="/")
    response.delete_cookie("Authorization", domain=DOMAIN, path="/")
    return response


@app.get("/login_basic")
def login_basic(auth: BasicAuth = Depends(basic_auth), db: Session = Depends(get_db)):
    if not auth:
        response = Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)
        return response

    try:
        decoded = base64.b64decode(auth).decode("ascii")  # type: ignore
        username, _, password = decoded.partition(":")
        user = crud.get_user_by_name(db, username=username)
        if not user:
            raise HTTPException(status_code=400, detail="Incorrect email or password")
        access_token = create_access_token(data={"sub": user.id}, key=KEY)
        token = jsonable_encoder(access_token)
        response = RedirectResponse(url="/")
        response.set_cookie(
            "Authorization", value=f"Bearer {token}", domain=DOMAIN, httponly=True, max_age=86400 * 7, path="/"
        )
        return response

    except BaseException:
        logger.exception("Excpetion")
        response = Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)
        return response


@app.on_event("startup")
def startup():
    # TODO : Add Periodic Task To Delete Expired Magic Links
    pass


@app.get("/")
def read_root() -> str:
    return "Welcome to Pylinks"


@app.post(
    "/user/", responses={400: {"detail": "Username Already Registered"}}, response_model=schemas.UserCreated,
)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)) -> schemas.UserCreated:
    user_in_db = crud.get_user_by_name(db, user.username)
    if user_in_db:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    user = crud.create_user(db, user.username, ph.hash(user.password))
    return schemas.UserCreated(username=user.username, created=user.created)


@app.post(
    "/team/",
    responses={400: {"detail": "Teamname Not Unique or Invalid Admin"}, 500: {"detail": "Transaction Rolledback"}},
    response_model=schemas.TeamCreated,
)
def create_team(
    *,
    teamname: str = Query(..., max_length=25),
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> schemas.TeamCreated:
    admin_user = crud.get_user_by_id(db, user_id)
    if not admin_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid User")

    team = crud.get_team_by_name(db, teamname)
    if team:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Teamname already registered")

    team = crud.create_team(db=db, teamname=teamname, admin=admin_user)

    return schemas.TeamCreated(teamname=team.teamname, created=team.created)


@app.get(
    "/team/", response_model=List[schemas.TeamBase],
)
def list_teams(
    user_id: int = Depends(get_current_user), db: Session = Depends(get_db),
):
    roles = crud.get_team_roles(db, user_id=user_id)
    teams = [role.team for role in roles]
    return [schemas.TeamBase(teamname=team.teamname) for team in teams]


@app.post(
    "/invite/", responses={400: {"details": "Invalid Teamname"}}, response_model=schemas.InviteCreated,
)
def create_invite(
    teamname: str = Query(..., max_length=25),
    role: UserRole = UserRole.READER,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user),
):
    team = crud.get_team_by_name(db, teamname)
    if not team:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Teamname")

    user_role = crud.get_team_roles(db, team.id, user_id, role=UserRole.ADMIN)
    if not user_role:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not Enough Permission")

    team_invites = crud.get_invites(db, team, role=role)
    if not team_invites:
        id, expiry = crud.create_invite(db, team, role)
    else:
        id = team_invites[0].id
        expiry = team_invites[0].expiry

    return {"id": id, "expiry": expiry, "link": f"https://{DOMAIN}/invite/{id}"}


@app.get("/invite/", responses={400: {"details": "Invalid Teamname"}, 404: {"details": "Invalid Link"}})
def accept_invite(link_id: uuid.UUID, db: Session = Depends(get_db), user_id: int = Depends(get_current_user)):
    user = crud.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Username")

    team_invite = crud.get_invite_by_id(db, link_id)
    if not team_invite:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid Link")

    if team_invite.expiry <= datetime.datetime.utcnow():
        crud.delete_invite(db, team_invite)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid Link")

    user_team_roles = crud.get_team_roles(db, team_id=team_invite.team_id, user_id=user.id)

    if not user_team_roles:
        crud.accept_invite(db, team_invite=team_invite, user=user)
    else:
        crud.upgrade_team_role(db, user_team_roles[0], team_invite.role_id)

    return HTMLResponse(status_code=status.HTTP_200_OK)


@app.post("/link/", responses={400: {"details": "Invalid Username"}, 409: {"details": "Link Already Registered"}})
def create_link(link: schemas.LinkCreate, db: Session = Depends(get_db), user_id: int = Depends(get_current_user)):
    if link.team:
        team = crud.get_team_by_name(db, teamname=link.team)
        if not team:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Team Name")
        user_role = crud.get_team_roles(db, team.id, user_id)

        if not user_role:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Insufficient Permission")

        user_role = user_role[0]
        if user_role.role_id == USER_ROLE_MAP[UserRole.READER]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Insufficient Permission")

        link_in_db = crud.get_team_link(db, text=link.text, team_id=team.id)
        if link_in_db:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Link Already Exists")

        crud.create_team_link(db, link.link, team.id, text=link.text)
        return HTMLResponse(status_code=status.HTTP_200_OK)

    else:
        link_in_db = crud.get_user_link(db, text=link.text, user_id=user_id)
        if link_in_db:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Link Already Exists")

        crud.create_user_link(db, link.link, user_id=user_id, text=link.text)
        return HTMLResponse(status_code=status.HTTP_200_OK)


@app.get("/link", responses={400: {"details": "Invalid User"}, 404: {"details:": "Link Doesn't Exist"}})
def get_link(
    text: str = Query(..., max_length=25),
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db),
    redirect: bool = True,
) -> Union[Dict[str, str], RedirectResponse]:
    link = crud.get_user_link(db, text, user_id)

    if not link:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Link Not found")

    if not redirect:
        return {"link": link.link}

    return RedirectResponse(url=link.link)


@app.get("/lro")
def get_lro(user_id: int = Depends(get_current_user), db: Session = Depends(get_db)) -> Union[List[schemas.TeamBase]]:
    user = crud.get_user_by_id(db, user_id)
    mro = user.lro
    if mro is None:
        return []

    team_ids = list(map(int, mro.split(",")))
    teams = crud.get_teams_by_ids(db, team_ids)

    team_name_dict = {team.id: team.teamname for team in teams}

    return [schemas.TeamBase(teamname=team_name_dict[id]) for id in team_ids]


@app.put("/lro")
def set_lro(lro: schemas.LROUpdate, user_id: int = Depends(get_current_user), db: Session = Depends(get_db)):
    user = crud.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User Record Not Found")

    if not lro.teams:
        crud.set_lro(db, user, lro="")
        return HTMLResponse(status_code=status.HTTP_200_OK)

    teams = crud.get_teams_by_names(db, lro.teams)
    teams_ids_dict = {team.teamname: team.id for team in teams}

    if len(teams) < len(lro.teams):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Teamname")

    team_ids = [team.id for team in teams]
    user_roles = crud.get_user_team_roles(db, user.id, team_ids=team_ids)

    if len(user_roles) < len(teams):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Insufficient Privilege")

    for role in user_roles:
        print(role)

    lro_str = ",".join([str(teams_ids_dict[teamname]) for teamname in lro.teams])
    crud.set_lro(db, user, lro_str)
    return HTMLResponse(status_code=status.HTTP_200_OK)
