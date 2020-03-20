from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from pylinks.constants import UserRole


class TeamRole(BaseModel):
    user_id: int
    team_id: int
    role: UserRole = UserRole.READER


class Team(BaseModel):
    id: Optional[int] = None
    team_name: str
    created: Optional[datetime] = None


class User(BaseModel):
    id: Optional[int] = None
    username: str
    created: Optional[datetime] = None
