import logging

from fastapi import Depends, FastAPI, HTTPException, Query, status
from sqlalchemy.orm import Session

from pylinks import crud, schemas
from pylinks.database import SessionLocal, engine
from pylinks.models import Base

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

Base.metadata.create_all(bind=engine)

app = FastAPI()


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
