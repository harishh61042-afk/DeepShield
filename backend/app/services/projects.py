from fastapi import HTTPException
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.entities import Project, ProjectMember, User


def can_view_project(db: Session, user: User, project: Project) -> bool:
    return user.role == "administrator" or project.owner_id == user.id or db.scalar(select(ProjectMember.id).where(ProjectMember.project_id == project.id, ProjectMember.user_id == user.id)) is not None


def get_project(db: Session, user: User, project_id, *, write=False) -> Project:
    project = db.get(Project, project_id)
    if not project or not can_view_project(db, user, project):
        raise HTTPException(status_code=404, detail="Project not found")
    if write and user.role != "administrator" and project.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Project owner permission required")
    return project


def project_accessible_query(db: Session, user: User):
    if user.role == "administrator":
        return select(Project)
    member_project = select(ProjectMember.project_id).where(ProjectMember.user_id == user.id)
    return select(Project).where(or_(Project.owner_id == user.id, Project.id.in_(member_project)))
