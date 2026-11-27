import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request, Response, status
from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.entities import SessionRecord, User

password_hash = PasswordHash.recommended()
SESSION_COOKIE = "depshield_session"
CSRF_COOKIE = "depshield_csrf"


def digest(value: str) -> str:
    key = settings.app_secret.encode("utf-8") if settings.app_secret else b"depshield-local-development-key"
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_password(plain: str) -> str:
    return password_hash.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return password_hash.verify(plain, hashed)
    except Exception:
        return False


def create_session(db: Session, user: User, response: Response) -> str:
    raw = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    db.add(SessionRecord(user_id=user.id, token_hash=digest(raw), expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.session_ttl_hours)))
    response.set_cookie(SESSION_COOKIE, raw, max_age=settings.session_ttl_hours * 3600, httponly=True, secure=settings.cookie_secure, samesite="strict", path="/api/v1")
    response.set_cookie(CSRF_COOKIE, csrf, max_age=settings.session_ttl_hours * 3600, httponly=False, secure=settings.cookie_secure, samesite="strict", path="/api/v1")
    return csrf


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/api/v1", secure=settings.cookie_secure, httponly=True, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/api/v1", secure=settings.cookie_secure, httponly=False, samesite="strict")


def current_user(request: Request, db: Session) -> User:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw or len(raw) > 200:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    record = db.scalar(select(SessionRecord).where(SessionRecord.token_hash == digest(raw), SessionRecord.revoked_at.is_(None), SessionRecord.expires_at > datetime.now(timezone.utc)))
    user = db.get(User, record.user_id) if record else None
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return user


def require_csrf(request: Request) -> None:
    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get("x-csrf-token")
    if not cookie or not header or not secrets.compare_digest(cookie, header):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") not in {item.rstrip("/") for item in settings.cors_origins}:
        raise HTTPException(status_code=403, detail="Request origin is not allowed")


def require_role(user: User, *roles: str) -> None:
    if user.role not in roles:
        raise HTTPException(status_code=403, detail="This action is not permitted")
