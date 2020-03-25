import logging
import uuid
from typing import List, Optional

from sqlalchemy.orm import Session

from pylinks import models, schemas
from pylinks.constants import USER_ROLE_MAP, UserRole

logger = logging.getLogger(__name__)


def get_user_by_name(db: Session, username: str) -> models.User:
    logger.info("Fetch User=%s", username)
    return db.query(models.User).filter(models.User.username == username).first()


def get_user_by_id(db: Session, user_id: int) -> models.User:
    return db.query(models.User).filter(models.User.id == user_id).first()


def create_user(db: Session, username: str, password_hash: str) -> models.User:
    user = models.User(username=username, password_hash=password_hash)
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("Created user: username=%s, id=%s", user.username, user.id)
    return user


def get_team(db: Session, teamname: str) -> models.Team:
    logger.info("Fetch Team=%s", teamname)
    return db.query(models.Team).filter(models.Team.teamname == teamname).first()


def create_team(db: Session, teamname: str, admin: schemas.User) -> models.Team:
    team = models.Team(teamname=teamname)
    try:
        db.add(team)
        db.flush()
        logger.info("Created team: teamname=%s, id=%s", team.teamname, team.id)
        team_role = models.TeamRole(team_id=team.id, user_id=admin.id, role_id=USER_ROLE_MAP[UserRole.ADMIN])
        db.add(team_role)
        logger.info("Created Admin Role: team_name=%s, user=%s", team.teamname, admin.username)
        db.commit()

    except BaseException:
        logger.exception("Transaction Commit Failed")
        db.rollback()
        logger.info("Team Creation Rollbacked team: teamname=%s, id=%s", team.teamname, team.id)
        raise Exception("Transaction Rolledback")

    db.refresh(team)
    return team


def create_team_role(db: Session, team_id: int, user_id: int, role_id: int):
    team_role = models.TeamRole(team_id=team_id, user_id=user_id, role_id=role_id)
    db.add(team_role)
    db.commit()
    logger.info("Created Team Role, Team_id:%s, User_id:%s, Role:%s", team_id, user_id, role_id)


def upgrade_team_role(db: Session, team_role: models.TeamRole, role_id: int):
    if team_role.role_id < role_id:
        team_role.role_id = role_id
        db.commit()


def delete_team_role(db: Session, team_id: int, user_id: int, role: UserRole) -> int:
    """
    Deletes a Team Role

    Args:
        db: Database Session
        team_id: Team ID
        user_id: User ID
        role: Role which is to be deleted

    Returns:
        Number of rows deleted
    """
    return (
        db.query(models.TeamRole)
        .filter(models.TeamRole.team_id == team_id)
        .filter(models.TeamRole.user_id == user_id)
        .filter(models.TeamRole.role_id == USER_ROLE_MAP[role])
        .delete()
    )


def get_team_roles(
    db: Session, team_id: Optional[int] = None, user_id: Optional[int] = None, role: Optional[UserRole] = None
) -> List[models.TeamRole]:
    query = db.query(models.TeamRole)
    if team_id:
        query = query.filter(models.TeamRole.team_id == team_id)
    if user_id:
        query = query.filter(models.TeamRole.user_id == user_id)
    if role:
        query = query.filter(models.TeamRole.role_id == USER_ROLE_MAP[role])
    return query.all()


def create_invite(db: Session, team: schemas.Team, role: UserRole):
    role_id = USER_ROLE_MAP[role]
    invite = models.TeamInvite(team_id=team.id, role_id=role_id)
    db.add(invite)
    db.commit()
    logger.info("Created Invite Team:%s, Role%s", team.id, role)
    return invite.id, invite.expiry


def get_invites(db: Session, team: schemas.Team, role: Optional[UserRole] = None) -> List[models.TeamInvite]:
    query = db.query(models.TeamInvite).filter(models.TeamInvite.team_id == team.id)
    logger.info("Fetching Invite For Team_id:%s, role:%s", team.id, role)
    if role:
        query = query.filter(models.TeamInvite.role_id == USER_ROLE_MAP[role])

    return query.all()


def get_invite_by_id(db: Session, id: uuid.UUID) -> Optional[models.TeamInvite]:
    logger.info("Fetch for TeamInvite:%s", id)
    return db.query(models.TeamInvite).filter(models.TeamInvite.id == id).first()


def delete_invite(db: Session, invite: models.TeamInvite) -> None:
    db.delete(invite)
    db.commit()


def create_user_link(db: Session, link: str, user_id: int, text: str):
    user_link = models.UserLink(link=link, user_id=user_id, text=text)
    db.add(user_link)
    db.commit()


def get_user_link(db: Session, text: str, user_id: int) -> models.UserLink:
    return (
        db.query(models.UserLink)
        .filter(models.UserLink.text == text)
        .filter(models.UserLink.user_id == user_id)
        .first()
    )


def create_team_link(db: Session, link: str, team_id: int, text: str):
    team_link = models.TeamLink(link=link, team_id=team_id, text=text)
    db.add(team_link)
    db.commit()


def get_team_link(db: Session, text: str, team_id: int) -> models.TeamLink:
    return (
        db.query(models.TeamLink)
        .filter(models.TeamLink.text == text)
        .filter(models.TeamLink.team_id == team_id)
        .first()
    )
