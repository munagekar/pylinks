import datetime

from sqlalchemy import DATETIME, Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from .constants import USER_ROLE_MAP, UserRole
from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(25), unique=True, index=True, nullable=False)
    created = Column(DATETIME, nullable=False)

    team_roles = relationship("TeamRole")


class Team(Base):
    __tablename__ = "teams"

    id = Column(Integer, primary_key=True, index=True)
    teamname = Column(String(25), unique=True, index=True, nullable=False)
    created = Column(DATETIME, nullable=False, default=datetime.datetime.utcnow)

    users = relationship("TeamRole")


class TeamRole(Base):
    __tablename__ = "team_roles"

    team_id = Column(Integer, ForeignKey("teams.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    role_id = Column(Integer, default=USER_ROLE_MAP[UserRole.READER])

    team = relationship("Team")
    user = relationship("User")
