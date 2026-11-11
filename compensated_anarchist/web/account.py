"""The dashboard's sign-in account: one username and password, created at first setup on the host.

The password is never stored. The file keeps a random salt and an scrypt hash of the password (memory-hard, so
guessing is slow even with the file in hand), in config/secrets/ (directory 0700, file 0600). Signing in to
the dashboard takes this account AND the access token that is generated fresh every time the dashboard starts.

Manage it on the host: `canarchist account create | passwd | reset | status`.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

N, R, P, DKLEN = 2 ** 15, 8, 1, 32  # scrypt cost: ~32 MiB and ~0.1 s per check
MAXMEM = 64 * 1024 * 1024
MIN_PASSWORD = 12
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")


def default_path(cfg) -> Path:
    raw = str((cfg.raw.get("dashboard") or {}).get("account_file") or "secrets/dashboard_account.json")
    p = Path(os.path.expanduser(raw))
    return p if p.is_absolute() else cfg.root / p


def _hash(password: str, salt: bytes, n: int = N, r: int = R, p: int = P) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=MAXMEM, dklen=DKLEN)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def check_new(username: str, password: str) -> None:
    if not USERNAME_RE.match(username or ""):
        raise ValueError("username: 1-64 letters, digits or . _ @ -")
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"password: at least {MIN_PASSWORD} characters")
    if password.strip().lower() == username.strip().lower():
        raise ValueError("password: must not be the username")


def load(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) and data.get("hash") and data.get("username") else None


def exists(path: Path) -> bool:
    return load(path) is not None


def save(path: Path, username: str, password: str) -> None:
    """Create or replace the account (the caller has confirmed a replacement)."""
    check_new(username, password)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    salt = secrets.token_bytes(16)
    now = datetime.now(timezone.utc).isoformat()[:19] + "Z"
    old = load(path)
    data = {"username": username, "scheme": "scrypt", "n": N, "r": R, "p": P, "salt": _b64(salt),
            "hash": _b64(_hash(password, salt)), "created": (old or {}).get("created", now), "updated": now}
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


_DUMMY_SALT = secrets.token_bytes(16)


def verify(path: Path, username: str, password: str) -> bool:
    """Constant-time check of both fields; the scrypt work is done even when the account or username is wrong."""
    acct = load(path)
    if not acct:
        _hash(password or "", _DUMMY_SALT)
        return False
    try:
        salt = base64.b64decode(acct["salt"])
        want = base64.b64decode(acct["hash"])
        got = _hash(password or "", salt, int(acct.get("n", N)), int(acct.get("r", R)), int(acct.get("p", P)))
    except (KeyError, ValueError, TypeError):
        return False
    user_ok = hmac.compare_digest(str(username or "").encode(), str(acct["username"]).encode())
    return hmac.compare_digest(got, want) and user_ok


# ---- interactive (CLI and scripts) -------------------------------------------------------------------
def _ask_new_password(username: str) -> str:
    while True:
        pw = getpass.getpass(f"  New password (at least {MIN_PASSWORD} characters): ")
        try:
            check_new(username, pw)
        except ValueError as e:
            print(f"  {e}")
            continue
        if getpass.getpass("  Repeat the password: ") != pw:
            print("  The passwords do not match. Try again.")
            continue
        return pw


def interactive(path: Path, action: str) -> int:
    """canarchist account <action>: status | create | passwd | reset. Returns a process exit code."""
    acct = load(path)
    if action == "status":
        if acct:
            print(f"Dashboard account: {acct['username']} (created {acct.get('created')}, password changed "
                  f"{acct.get('updated')})\nStored as a salted scrypt hash in {path}")
            return 0
        print(f"No dashboard account yet. Create it with: canarchist account create  ({path})")
        return 1
    if action == "create":
        if acct:
            print(f"The dashboard account already exists ({acct['username']}). Use `canarchist account passwd` to "
                  f"change the password, or `canarchist account reset` if it is forgotten.")
            return 1
        print("Create the dashboard sign-in account. You will sign in with it plus the access token that each start prints.")
        while True:
            username = input("  Username: ").strip()
            if USERNAME_RE.match(username):
                break
            print("  1-64 letters, digits or . _ @ -")
        save(path, username, _ask_new_password(username))
        print(f"Account '{username}' created. The password is stored only as a salted scrypt hash ({path}, mode 600).")
        return 0
    if action == "passwd":
        if not acct:
            print("No dashboard account yet. Create it with: canarchist account create")
            return 1
        if not verify(path, acct["username"], getpass.getpass(f"  Current password for {acct['username']}: ")):
            print("That is not the current password. (Forgotten? `canarchist account reset` replaces the account.)")
            return 1
        save(path, acct["username"], _ask_new_password(acct["username"]))
        print("Password changed. Signed-in browsers keep their session until it idles out or the dashboard restarts.")
        return 0
    if action == "reset":
        if acct and input(f"  Replace the account '{acct['username']}'? Type reset to confirm: ").strip() != "reset":
            print("Nothing changed.")
            return 1
        if acct:
            Path(path).unlink()
        return interactive(path, "create")
    raise ValueError(f"unknown account action {action}")
