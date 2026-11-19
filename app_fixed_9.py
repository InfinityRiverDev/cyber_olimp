import hmac
import os
import secrets
import sqlite3
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask,
    abort,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)

app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE="Lax",
)

DB = "forum.db"

PAGE = """
<!doctype html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Мини-форум</title>
</head>
<body>
    <h1>Мини-форум</h1>

    <h2>Комментарии</h2>

    {% for author, text in comments %}
        <article>
            <b>{{ author|e }}</b>
            <p>{{ text|e }}</p>
        </article>
    {% else %}
        <p>Комментариев пока нет.</p>
    {% endfor %}

    <h2>Добавить комментарий</h2>

    <form method="post" action="{{ url_for('comment') }}">
        <input type="hidden" name="csrf_token" value="{{ csrf }}">

        <label>
            Автор:
            <input name="author" maxlength="100" required>
        </label>

        <br>

        <label>
            Текст:
            <textarea name="text" maxlength="5000" required></textarea>
        </label>

        <br>
        <button type="submit">Добавить</button>
    </form>
</body>
</html>
"""


def db():
    return sqlite3.connect(DB)


def init():
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY,
                author TEXT NOT NULL,
                text TEXT NOT NULL
            )
            """
        )


def csrf_token():
    session.setdefault("csrf_token", secrets.token_urlsafe(32))
    return session["csrf_token"]


def require_csrf(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")

        origin = request.headers.get("Origin")
        if origin:
            parsed = urlparse(origin)
            if parsed.netloc != request.host:
                abort(403)

        if not expected:
            abort(403)

        if not hmac.compare_digest(supplied, expected):
            abort(403)

        return fn(*args, **kwargs)

    return wrapper


@app.route("/")
def index():
    with db() as conn:
        rows = conn.execute(
            "SELECT author, text FROM comments ORDER BY id DESC"
        ).fetchall()

    return render_template_string(
        PAGE,
        comments=rows,
        csrf=csrf_token(),
    )


@app.post("/comment")
@require_csrf
def comment():
    author = request.form.get("author", "")[:100]
    text = request.form.get("text", "")[:5000]

    with db() as conn:
        conn.execute(
            "INSERT INTO comments (author, text) VALUES (?, ?)",
            (author, text),
        )

    return redirect(url_for("index"))


@app.post("/profile")
@require_csrf
def profile():
    user = session.get("user")

    if not user:
        return "no session", 401

    email = request.form.get("email", "")[:254]

    with db() as conn:
        conn.execute(
            "UPDATE comments SET author = ? WHERE author = ?",
            (email, user),
        )

    return "email updated"


@app.get("/setuser")
def setuser():
    abort(404)


@app.get("/search")
def search():
    q = request.args.get("q", "")[:200]

    return render_template_string(
        "Результаты по запросу: {{ q|e }}",
        q=q,
    )


@app.after_request
def headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; object-src 'none'; base-uri 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


if __name__ == "__main__":
    init()
    app.run(host="127.0.0.1", port=8080)
