import datetime
import logging
import uuid
from typing import Dict, Union

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse

from pylinks import crud, schemas
from pylinks.constants import UserRole
from pylinks.database import SessionLocal, engine
from pylinks.models import Base

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

Base.metadata.create_all(bind=engine)

app = FastAPI()


@app.on_event("startup")
def startup():
    # TODO : Add Periodic Task To Delete Expired Magic Links
    pass


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


@app.get("/")
def read_root() -> str:
    return "Welcome to Pylinks"


@app.post(
    "/user/", responses={400: {"detail": "Username Already Registered"}}, response_model=schemas.UserCreated,
)
def create_user(username: str = Query(..., max_length=25), db: Session = Depends(get_db)) -> schemas.UserCreated:
    user = crud.get_user(db, username)
    if user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    user = crud.create_user(db, username)
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
def create_link(userlink: schemas.UserLinkCreate, db: Session = Depends(get_db)):
    user = crud.get_user(db, userlink.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Username")

    link = crud.get_user_link(db, text=userlink.text, user_id=user.id)
    if link:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Link Already Exists")

    crud.create_user_link(db, userlink.link, user_id=user.id, text=userlink.text)
    return HTMLResponse(status_code=status.HTTP_200_OK)


@app.get("/ulink")
def get_link(
    text: str = Query(..., max_length=25),
    username: str = Query(..., max_length=25),
    db: Session = Depends(get_db),
    redirect: bool = True,
) -> Union[Dict[str, str], RedirectResponse]:
    user = crud.get_user(db, username)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Username")

    link = crud.get_user_link(db, text, user.id)

    if not link:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Link Not found")

    if not redirect:
        return {"link": link.link}

    return RedirectResponse(url=link.link)
