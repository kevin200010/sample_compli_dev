"""Utilities for password hashing and validation.

This module centralises password policy enforcement and hashing so the
application can migrate from legacy PBKDF2/Bcrypt values to Argon2id without
breaking existing accounts.  All helpers are side-effect free to make unit
testing straightforward.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app import bcrypt


@dataclass(frozen=True)
class Argon2Parameters:
    """Container for Argon2 configuration derived from environment variables."""

    time_cost: int = int(os.getenv("ARGON2_TIME_COST", "3"))
    memory_cost: int = int(os.getenv("ARGON2_MEMORY_COST", "65536"))
    parallelism: int = int(os.getenv("ARGON2_PARALLELISM", "2"))


_ARGON2_PARAMS = Argon2Parameters()
_argon2_hasher = PasswordHasher(
    time_cost=_ARGON2_PARAMS.time_cost,
    memory_cost=_ARGON2_PARAMS.memory_cost,
    parallelism=_ARGON2_PARAMS.parallelism,
)


def hash_password(password: str) -> str:
    """Hash a password using Argon2id.

    The encoded string contains metadata so the parameters can evolve without
    needing schema changes.  Argon2 raises a ``TypeError`` if ``password`` is
    not str, which is acceptable as a hard failure.
    """

    return _argon2_hasher.hash(password)


def verify_password(stored_hash: str, candidate: str) -> bool:
    """Verify a password against either Argon2id or legacy Bcrypt hashes."""

    if not stored_hash:
        return False

    if stored_hash.startswith("$argon2"):
        try:
            return _argon2_hasher.verify(stored_hash, candidate)
        except VerifyMismatchError:
            return False
    # Fallback to legacy Bcrypt hashes for backward compatibility.
    return bcrypt.check_password_hash(stored_hash, candidate)


_PASSWORD_POLICY = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$"
)


def validate_password(password: str) -> Optional[str]:
    """Validate a password against the policy.

    Returns ``None`` when the password is acceptable, otherwise a human-readable
    error message suitable for surfacing to API clients or UI forms.
    """

    if not password:
        return "Password is required."
    if not _PASSWORD_POLICY.match(password):
        return (
            "Password must be at least 12 characters and include upper, lower, "
            "numeric, and special characters."
        )
    return None


def needs_rehash(stored_hash: str) -> bool:
    """Return ``True`` when the stored hash should be upgraded to Argon2."""

    if not stored_hash:
        return True
    if stored_hash.startswith("$argon2"):
        return _argon2_hasher.check_needs_rehash(stored_hash)
    return True
