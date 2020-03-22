import logging

from sqlalchemy.orm import Session

from pylinks import models, schemas
from pylinks.constants import USER_ROLE_MAP, UserRole

logger = logging.getLogger(__name__)


def get_user(db: Session, username: str) -> models.User:
    logger.info("Fetch User=%s", username)
    return db.query(models.User).filter(models.User.username == username).first()


def create_user(db: Session, username: str) -> models.User:
    user = models.User(username=username)
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
        logger.info("Created Admin Role: team_id=%s, user_id=%s", team.id, admin.id)
        db.commit()

    except BaseException:
        logger.exception("Transaction Commit Failed")
        db.rollback()
        logger.info("Team Creation Rollbacked team: teamname=%s, id=%s", team.teamname, team.id)
        raise Exception("Transaction Rolledback")

    db.refresh(team)
    return team


def create_invite(db: Session, team: schemas.Team, role: UserRole):
    role_id = USER_ROLE_MAP[role]
    invite = models.TeamInvite(team_id=team.id, role_id=role_id)
    db.add(invite)
    db.commit()
    return invite.id, invite.expiry
