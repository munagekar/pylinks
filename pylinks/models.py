import datetime

from sqlalchemy import DATETIME, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from .constants import USER_ROLE_MAP, UserRole
from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(25), unique=True, index=True, nullable=False)
    created = Column(DATETIME, nullable=False, default=datetime.datetime.utcnow)

    team_roles = relationship("TeamRole")


class Team(Base):
    __tablename__ = "teams"

    id = Column(Integer, primary_key=True, index=True)
    teamname = Column(String(25), unique=True, index=True, nullable=False)
    created = Column(DATETIME, nullable=False, default=datetime.datetime.utcnow)

    users = relationship("TeamRole")


class TeamRole(Base):
    __tablename__ = "team_roles"

    row_id = Column(Integer, primary_key=True)
    team_id = Column(Integer, ForeignKey("teams.id"), index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    role_id = Column(Integer, default=USER_ROLE_MAP[UserRole.READER])

    team = relationship("Team")
    user = relationship("User")
