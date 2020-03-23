import base64
import datetime
import logging
import uuid
from typing import Dict, Union

import argon2  # type: ignore
import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse, Response

from pylinks import config, crud, schemas
from pylinks.auth import BasicAuth, OAuth2PasswordBearerCookie, create_access_token
from pylinks.constants import UserRole
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
KEY = config.read_from_env().key


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    try:
        ph.verify(plain_password, hashed_password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False


def get_current_user(token: str = Depends(oauth2_scheme)) -> int:
    print(f"Token :%s", token)
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


@app.post("/token", response_model=schemas.Token)
def route_login_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.get_user(db, username=form_data.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect username or password")

    if not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect Username or password")

    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(form_data.password)
        logger.info("Rehash Password for user:%s", user.username)
        db.commit()

    access_token = create_access_token(data={"sub": user.username}, key=KEY)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/logout")
def route_logout_and_remove_cookie():
    response = RedirectResponse(url="/")
    response.delete_cookie("Authorization", domain="localtest.me")
    return response


@app.get("/login_basic")
def login_basic(auth: BasicAuth = Depends(basic_auth), db: Session = Depends(get_db)):
    print("Inside Login Basic")
    if not auth:
        print("No Authentication")
        response = Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)
        return response

    try:
        decoded = base64.b64decode(auth).decode("ascii")  # type: ignore
        username, _, password = decoded.partition(":")
        user = crud.get_user(db, username=username)
        print("Got User")
        if not user:
            raise HTTPException(status_code=400, detail="Incorrect email or password")
        print("Creating Access Token")
        access_token = create_access_token(data={"sub": user.id}, key=KEY)
        print("Created Adccess Token")
        token = jsonable_encoder(access_token)
        response = RedirectResponse(url="/docs")
        print("Set Cookie")
        response.set_cookie(
            "Authorization", value=f"Bearer {token}", domain="localhost.com", httponly=True, max_age=86400 * 7,
        )
        print("Set Cookie Okay")
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
def create_user(
    username: str = Query(..., max_length=25), password: str = Query(..., max_length=25), db: Session = Depends(get_db)
) -> schemas.UserCreated:
    user = crud.get_user(db, username)
    if user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    user = crud.create_user(db, username, ph.hash(password))
    return schemas.UserCreated(username=user.username, created=user.created)


@app.post(
    "/team/",
    responses={400: {"detail": "Teamname Not Unique or Invalid Admin"}, 500: {"detail": "Transaction Rolledback"}},
    response_model=schemas.TeamCreated,
)
def create_team(
    *, teamname: str = Query(..., max_length=25), admin: str = Query(..., max_length=25), db: Session = Depends(get_db)
) -> schemas.TeamCreated:
    admin_user = crud.get_user(db, admin)
    if not admin_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Admin")

    team = crud.get_team(db, teamname)
    if team:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Teamname already registered")

    team = crud.create_team(db=db, teamname=teamname, admin=admin_user)

    return schemas.TeamCreated(teamname=team.teamname, created=team.created)


@app.post(
    "/invite/", responses={400: {"details": "Invalid Teamname"}}, response_model=schemas.InviteCreated,
)
def create_invite(
    teamname: str = Query(..., max_length=25), role: UserRole = UserRole.READER, db: Session = Depends(get_db)
):
    team = crud.get_team(db, teamname)
    if not team:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Teamname")

    id, expiry = crud.create_invite(db, team, role)
    return {"id": id, "expiry": expiry}


@app.get("/invite/", responses={400: {"details": "Invalid Teamname"}, 404: {"details": "Invalid Link"}})
def accept_invite(id: uuid.UUID, username: str = Query(..., max_length=25), db: Session = Depends(get_db)):
    user = crud.get_user(db, username)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Username")

    team_invite = crud.get_invite_by_id(db, id)
    if not team_invite or team_invite.expiry <= datetime.datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid Link")

    user_team_role = crud.get_team_roles(db, team_id=team_invite.team_id, user_id=user.id)

    if not user_team_role:
        crud.create_team_role(db, team_id=team_invite.team_id, user_id=user.id, role_id=team_invite.role_id)
    else:
        user_team_role = user_team_role[0]
        user_team_role.role_id = max(team_invite.role_id, user_team_role.role_id)
        db.commit()

    return HTMLResponse(status_code=status.HTTP_200_OK)


@app.post("/ulink/", responses={400: {"details": "Invalid Username"}, 409: {"details": "Link Already Registered"}})
def create_link(
    userlink: schemas.UserLinkCreate, db: Session = Depends(get_db), user_id: int = Depends(get_current_user)
):
    link = crud.get_user_link(db, text=userlink.text, user_id=user_id)
    if link:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Link Already Exists")

    crud.create_user_link(db, userlink.link, user_id=user_id, text=userlink.text)
    return HTMLResponse(status_code=status.HTTP_200_OK)


@app.get("/ulink", responses={400: {"details": "Invalid User"}, 404: {"details:": "Link Doesn't Exist"}})
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


# @app.get("/openapi.json")
# def get_open_api_endpoint(user_id: int = Depends(get_current_user())):
#     return JSONResponse(get_openapi(title="FastAPI", version="1", routes=app.routes))
#
#
# @app.get("/docs")
# def get_documentation(user_id: int = Depends(get_current_user)):
#     return get_swagger_ui_html(openapi_url="/openapi.json", title="docs")
