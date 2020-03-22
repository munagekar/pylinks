import datetime
import uuid

from sqlalchemy import DATETIME, Column, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.types import CHAR, TypeDecorator

from .constants import USER_ROLE_MAP, UserRole
from .database import Base


class GUID(TypeDecorator):
    """Platform-independent GUID type.

    Uses Postgresql's UUID type, otherwise uses
    CHAR(32), storing as stringified hex values.

    """

    impl = CHAR

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == "postgresql":
            return str(value)
        else:
            if not isinstance(value, uuid.UUID):
                return "%.32x" % uuid.UUID(value).int
            else:
                # hexstring
                return "%.32x" % value.int

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        else:
            if not isinstance(value, uuid.UUID):
                value = uuid.UUID(value)
            return value


def utcnow_more_7_days():
    return datetime.datetime.utcnow() + datetime.timedelta(days=7)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(25), unique=True, index=True, nullable=False)
    created = Column(DATETIME, nullable=False, default=datetime.datetime.utcnow)

    team_roles = relationship("TeamRole", cascade="all, delete", passive_deletes=True)  # type: ignore


class Team(Base):
    __tablename__ = "teams"

    id = Column(Integer, primary_key=True, index=True)
    teamname = Column(String(25), unique=True, index=True, nullable=False)
    created = Column(DATETIME, nullable=False, default=datetime.datetime.utcnow)

    users = relationship("TeamRole", cascade="all,delete", passive_deletes=True)  # type: ignore
    invites = relationship("TeamInvite", cascade="all,delete", passive_deletes=True)  # type: ignore


class TeamRole(Base):
    __tablename__ = "team_roles"
    __table_args__ = (UniqueConstraint("team_id", "user_id"),)
    row_id = Column(Integer, primary_key=True)
    team_id = Column(Integer, ForeignKey("teams.id"), index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    role_id = Column(Integer, default=USER_ROLE_MAP[UserRole.READER])

    team = relationship("Team")  # type: ignore
    user = relationship("User")  # type: ignore


class TeamInvite(Base):
    __tablename__ = "team_invites"
    __table_args__ = (UniqueConstraint("team_id", "role_id"),)

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    team_id = Column(Integer, ForeignKey("teams.id"), index=True)
    role_id = Column(Integer, default=USER_ROLE_MAP[UserRole.READER])
    expiry = Column(DATETIME, default=utcnow_more_7_days)
