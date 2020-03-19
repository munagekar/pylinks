import logging
import sqlite3
from datetime import datetime

import databases
import sqlalchemy
from fastapi import FastAPI, HTTPException, Path, status
from pydantic import BaseModel

logging.basicConfig()
logger = logging.Logger(__name__)
logger.setLevel(logging.INFO)


class User(BaseModel):
    id: int
    username: str
    created: datetime


class Team(BaseModel):
    id: int
    teamname: str
    created: datetime


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
