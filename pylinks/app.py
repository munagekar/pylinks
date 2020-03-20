import logging
import sqlite3
from datetime import datetime
from enum import Enum

import databases
import sqlalchemy
from fastapi import FastAPI, HTTPException, Path, Query, status

from pylinks.models import Team, User

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class UserRole(str, Enum):
    READER = "reader"
    WRITER = "writer"
    ADMIN = "admin"


USER_ROLE_MAP = {UserRole.READER: 0, UserRole.WRITER: 1, UserRole.ADMIN: 1}

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
async def startup() -> None:
    await database.connect()


@app.on_event("shutdown")
async def shutdown() -> None:
    await database.disconnect()


@app.get("/")
async def read_root() -> str:
    return "Welcome to Pylinks"


@app.post(
    "/user/{username}",
    responses={400: {"detail": "Username Not Unique"}},
    response_model=User,
    response_model_exclude={"id"},
)
async def create_user(username: str = Path(..., max_length=25)) -> User:
    try:
        created = datetime.utcnow()
        query = users.insert().values(username=username, created=created)
        user_id = await database.execute(query)
        logger.info("Created New User. User:%s Id:%s", username, user_id)
    except sqlite3.IntegrityError:
        logger.info("Failed to Create New User. User:%s already exists", username)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username Not Unique")

    return User(id=user_id, username=username, created=created)


@app.post(
    "/team/{team_name}",
    responses={400: {"detail": "Teamname Not Unique or Invalid Admin"}, 500: {"detail": "Transaction Rolledback"}},
    response_model=Team,
    response_model_exclude={"id"},
)
async def create_team(*, team_name: str = Path(..., max_length=25), admin: str = Query(..., max_length=25)) -> Team:
    query = users.select().where(users.c.username == admin)
    result = await database.fetch_val(query)

    if result is None:
        logger.info("Invalid Admin %s", admin)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Admin Username")

    created = datetime.utcnow()
    transaction = await database.transaction()
    try:
        try:
            query = teams.insert().values(teamname=team_name, created=created)
            team_id = await database.execute(query)
        except sqlite3.IntegrityError:
            logger.info("Failed to Create New Team. Team:%s already exists", team_name)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Teamname Not Unique")
    except HTTPException as e:
        await transaction.rollback()
        raise e
    except BaseException:
        logger.critical("Transaction Failed!")
        await transaction.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Transaction Rolledback")
    else:
        await transaction.commit()
        logger.info("Created New Team. Team:%s Id:%s", team_name, team_id)

    return Team(id=team_id, team_name=team_name, created=created)
