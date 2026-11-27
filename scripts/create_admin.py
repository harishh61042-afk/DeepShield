"""Create an administrator interactively; no default password is provided."""
import getpass
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend" if (ROOT / "backend" / "app").is_dir() else Path("/app")
sys.path.insert(0, str(BACKEND))

from sqlalchemy import select  # noqa: E402
from app.core.database import SessionLocal  # noqa: E402
from app.models.entities import User  # noqa: E402
from app.security.auth import hash_password  # noqa: E402


def main():
    email = input("Administrator email: ").strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise SystemExit("Enter a valid email address.")
    name = input("Display name: ").strip()
    if not name or len(name) > 100:
        raise SystemExit("Display name must be between 1 and 100 characters.")
    password = getpass.getpass("Password (12+ characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 12 or len(password) > 128 or password != confirmation:
        raise SystemExit("Passwords must match and contain 12 to 128 characters.")
    with SessionLocal.begin() as db:
        if db.scalar(select(User.id).where(User.email == email)):
            raise SystemExit("An account with that email already exists.")
        db.add(User(email=email, display_name=name, password_hash=hash_password(password), role="administrator", is_active=True))
    print("Administrator account created.")


if __name__ == "__main__":
    main()
