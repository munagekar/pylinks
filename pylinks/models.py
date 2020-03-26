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


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(25), unique=True, index=True, nullable=False)
    created = Column(DATETIME, nullable=False, default=datetime.datetime.utcnow)
    password_hash = Column(String(), nullable=False)
    lro = Column(String(), nullable=True)  # Link Resolution Order

    team_roles = relationship("TeamRole", cascade="all, delete", passive_deletes=True)  # type: ignore
    links = relationship("UserLink", cascade="all,delete", passive_deletes=True)  # type:ignore


class Team(Base):
    __tablename__ = "teams"

    id = Column(Integer, primary_key=True, index=True)
    teamname = Column(String(25), unique=True, index=True, nullable=False)
    created = Column(DATETIME, nullable=False, default=datetime.datetime.utcnow)

    roles = relationship("TeamRole", cascade="all,delete", passive_deletes=True)  # type: ignore
    invites = relationship("TeamInvite", cascade="all,delete", passive_deletes=True)  # type: ignore
    links = relationship("TeamLink", cascade="all,delete", passive_deletes=True)  # type:ignore


class UserLink(Base):
    __tablename__ = "user_links"
    __table_args__ = (UniqueConstraint("text", "user_id"),)

    row_id = Column(Integer, primary_key=True)
    text = Column(String(25), index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    link = Column(String())

    user = relationship("User")  # type: ignore


class TeamLink(Base):
    __tablename__ = "team_links"
    __table_args__ = (UniqueConstraint("text", "team_id"),)

    row_id = Column(Integer, primary_key=True)
    text = Column(String(25), index=True)
    team_id = Column(Integer, ForeignKey("teams.id"), index=True)
    link = Column(String())

    team = relationship("Team")  # type: ignore


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
    expiry = Column(DATETIME, default=lambda: datetime.datetime.utcnow() + datetime.timedelta(days=7))
