from enum import Enum


class UserRole(str, Enum):
    READER = "reader"
    WRITER = "writer"
    ADMIN = "admin"


USER_ROLE_MAP = {UserRole.READER: 0, UserRole.WRITER: 1, UserRole.ADMIN: 1}
