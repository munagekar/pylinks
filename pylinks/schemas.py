import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl

from pylinks.constants import UserRole


class UserBase(BaseModel):
    username: str


class UserCreated(UserBase):
    created: datetime = Field(default=datetime.utcnow())


class TeamBase(BaseModel):
    teamname: str


class TeamCreated(TeamBase):
    created: datetime = Field(default=datetime.utcnow())


class User(UserBase):
    id: int
    created: datetime

    team_roles: List["TeamRole"]

    class Config:
        orm_mode = True


class Team(TeamBase):
    id: int
    team_name: str
    created: Optional[datetime] = None

    users: List[User]

    class Config:
        orm_mode = True


class TeamRole(BaseModel):
    user_id: int
    team_id: int
    role: UserRole = UserRole.READER

    team: Team
    user: User

    class Config:
        orm_mode = True


class InviteCreated(BaseModel):
    id: uuid.UUID
    expiry: datetime


class UserLinkCreate(BaseModel):
    username: str
    text: str
    link: HttpUrl


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    user_id: int
