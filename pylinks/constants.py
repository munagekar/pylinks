from enum import Enum
from typing import Dict


class UserRole(str, Enum):
    READER = "reader"
    WRITER = "writer"
    ADMIN = "admin"


USER_ROLE_MAP: Dict[UserRole, int] = {UserRole.READER: 0, UserRole.WRITER: 1, UserRole.ADMIN: 1}
