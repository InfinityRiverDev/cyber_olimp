import hashlib
import hmac
import math
import os
import re
import secrets
import shutil
import sqlite3
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen

import yaml

DB_PATH = os.environ.get(
    "USERS_DB",
    "/var/lib/audit_me/users.db"
)

REPORT_ROOT = Path("/var/reports").resolve()
DATA_ROOT = Path("/data/users").resolve()


def safe_child(root, name):
    path = (root / name).resolve()

    if path != root and root not in path.parents:
        raise PermissionError("path outside allowed directory")

    return path


def run_ping(host):
    if not re.fullmatch(
        r"[A-Za-z0-9.-]{1,253}",
        host
    ):
        raise ValueError("invalid host")

    import subprocess

    return subprocess.run(
        ["ping", "-c", "1", "--", host],
        check=False,
        timeout=5
    ).returncode


def exec_formula(expr):
    raise ValueError(
        "arbitrary expression evaluation is disabled"
    )


def load_state(data):
    import json

    return json.loads(
        data.decode("utf-8")
    )


def read_yaml_config(text):
    return yaml.safe_load(text)


def find_user(conn, login):
    if not re.fullmatch(
        r"[A-Za-z0-9_.@-]{1,64}",
        login
    ):
        raise ValueError("invalid login")

    return conn.execute(
        """
        SELECT id, name, email
        FROM users
        WHERE name = ?
        """,
        (login,)
    ).fetchall()


def password_digest(pw, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        pw.encode(),
        salt,
        200000
    ).hex()


def generate_token():
    return secrets.token_urlsafe(32)


def read_report(name):
    path = safe_child(REPORT_ROOT, name)
    return path.read_text(
        encoding="utf-8"
    )


def save_tmp_report(content):
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix="report-",
        suffix=".tmp",
        delete=False
    ) as fh:
        fh.write(content)
        return fh.name


def check_and_read(path):
    target = Path(path).resolve()
    allowed = Path(
        "/var/lib/audit_me/data"
    ).resolve()

    if target != allowed and allowed not in target.parents:
        raise PermissionError("access denied")

    return target.read_text(
        encoding="utf-8"
    )


def authenticate(
    username,
    password,
    stored_hash,
    salt
):
    supplied = password_digest(
        password,
        salt
    )

    return (
        username != "" and
        hmac.compare_digest(
            supplied,
            stored_hash
        )
    )


def download_report(url, dest):
    parsed = urlparse(url)

    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(
            "only HTTPS URLs are allowed"
        )

    target = safe_child(
        REPORT_ROOT,
        dest
    )

    with urlopen(url, timeout=10) as response:
        data = response.read(
            5 * 1024 * 1024 + 1
        )

    if len(data) > 5 * 1024 * 1024:
        raise ValueError(
            "report is too large"
        )

    target.write_bytes(data)
    return str(target)


def average_stats(values):
    if not values:
        raise ValueError(
            "empty values"
        )

    numbers = [
        float(value)
        for value in values
    ]

    if not all(
        math.isfinite(value)
        for value in numbers
    ):
        raise ValueError(
            "non-finite value"
        )

    return sum(numbers) / len(numbers)


def parse_amount(raw):
    if not re.fullmatch(
        r"0|[1-9][0-9]{0,8}",
        raw
    ):
        raise ValueError(
            "invalid amount"
        )

    value = int(raw)

    if value > 100000000:
        raise ValueError(
            "amount is too large"
        )

    return value


def delete_user_files(username):
    if not re.fullmatch(
        r"[A-Za-z0-9_-]{1,64}",
        username
    ):
        raise ValueError(
            "invalid username"
        )

    target = safe_child(
        DATA_ROOT,
        username
    )

    if target.exists():
        shutil.rmtree(target)
