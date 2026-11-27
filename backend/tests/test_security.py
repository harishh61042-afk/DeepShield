from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.security.auth import digest, hash_password, require_role, verify_password


def test_password_hashing_uses_one_way_hash():
    plain = "correct horse battery staple"
    hashed = hash_password(plain)
    assert plain not in hashed
    assert verify_password(plain, hashed)
    assert not verify_password("wrong password", hashed)


def test_digest_is_keyed_and_role_check_denies_escalation(monkeypatch):
    monkeypatch.setattr(settings, "app_secret", "unit-test-secret-that-is-not-a-real-credential")
    first = digest("session-token")
    assert digest("session-token") == first
    monkeypatch.setattr(settings, "app_secret", "a-different-test-key")
    assert digest("session-token") != first

    developer = SimpleNamespace(role="developer")
    require_role(developer, "developer")
    with pytest.raises(HTTPException) as denied:
        require_role(developer, "administrator")
    assert denied.value.status_code == 403
