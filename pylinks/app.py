import logging
import sqlite3
from datetime import datetime
from enum import Enum
from typing import List, Optional

import databases
import sqlalchemy
from fastapi import FastAPI, HTTPException, Path, status
from pydantic import BaseModel

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class User(BaseModel):
    id: Optional[int] = None
    username: str
    created: Optional[datetime] = None


class Team(BaseModel):
    id: Optional[int] = None
    teamname: str
    created: Optional[datetime] = None


class UserRole(str, Enum):
    READER = "reader"
    WRITER = "writer"
    ADMIN = "admin"


USER_ROLE_MAP = {UserRole.READER: 0, UserRole.WRITER: 1, UserRole.ADMIN: 1}


class TeamRole(BaseModel):
    user: User
    team: Team
    role: UserRole = UserRole.READER


DATABASE_URL = "sqlite:///data/test.db"
database = databases.Database(DATABASE_URL)

metadata = sqlalchemy.MetaData()

users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String(25), unique=True, index=True, nullable=False),
    sqlalchemy.Column("created", sqlalchemy.DATETIME, nullable=False),
)

teams = sqlalchemy.Table(
    "teams",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("teamname", sqlalchemy.String(25), unique=True, index=True, nullable=False),
    sqlalchemy.Column("created", sqlalchemy.DATETIME, nullable=False),
)

team_roles = sqlalchemy.Table(
    "team_roles",
    metadata,
    sqlalchemy.Column("team_id", sqlalchemy.Integer, index=True, nullable=False),
    sqlalchemy.Column("user_id", sqlalchemy.Integer, index=True, nullable=False),
    sqlalchemy.Column("role_id", sqlalchemy.Integer, default=USER_ROLE_MAP[UserRole.READER]),
)

engine = sqlalchemy.create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

metadata.create_all(engine)

app = FastAPI()


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


@app.get("/")
async def read_root():
    return "Welcome to Pylinks"


@app.post("/user/{username}", responses={400: {"detail": "Username Not Unique"}})
async def create_user(username: str = Path(..., max_length=25)):
    try:
        created = datetime.utcnow()
        query = users.insert().values(username=username, created=created)
        user_id = await database.execute(query)
        logger.info("Created New User. User:%s Id:%s", username, user_id)
    except sqlite3.IntegrityError:
        logger.info("Failed to Create New User. User:%s already exists", username)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username Not Unique")

    return User(id=user_id, username=username, created=created)


@app.post("/team/{team_name}", responses={400: {"detail": "Teamname Not Unique"}})
async def create_team(*, team_name: str = Path(..., max_length=25), team_roles: List[TeamRole]):
    try:
        created = datetime.utcnow()
        query = teams.insert.values(teamname=team_name, created=created)
        team_id = await database.execute(query)
        logger.info("Created New Team. Team:%s Id:%s", team_name, team_id)
    except sqlite3.IntegrityError:
        logger.info("Failed to Create New Team. Team:%s already exists", team_name)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Teamname Not Unique")
