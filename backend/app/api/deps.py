from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import User
from app.security.auth import current_user


def authenticated_user(request: Request, db: Session = Depends(get_db)) -> User:
    return current_user(request, db)
