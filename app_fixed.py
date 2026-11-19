import logging
import re
import sqlite3
from pathlib import Path
from flask import Flask, abort, render_template_string, request

app = Flask(__name__)
DB = Path(__file__).with_name("shop.db")

logging.basicConfig(
    filename=Path(__file__).with_name("security.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

TPL = """
<h1>Магазин</h1>
<form method="get" action="/search">
<input name="q" placeholder="поиск товара">
<button>Найти</button>
</form>
<form method="post" action="/login">
<input name="login" placeholder="логин">
<input name="password" type="password" placeholder="пароль">
<button>Войти</button>
</form>
<pre>{{ result }}</pre>
"""

SAFE_TEXT = re.compile(r"^[\w .@+\-]{0,64}$", re.UNICODE)


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def valid_text(value):
    return len(value) <= 64 and SAFE_TEXT.fullmatch(value) is not None


@app.route("/")
def index():
    return render_template_string(TPL, result="")


@app.post("/login")
def login():
    login_value = request.form.get("login", "")
    password = request.form.get("password", "")

    if not valid_text(login_value) or not valid_text(password):
        logging.warning("Rejected login input")
        return "Неверные данные", 401

    query = """
        SELECT id, username, role
        FROM users
        WHERE username = ? AND password_hash = ?
    """

    with db() as conn:
        row = conn.execute(
            query, (login_value, password)
        ).fetchone()

    if row:
        return f"Добро пожаловать, {row['username']} (роль: {row['role']})"

    return "Неверные данные", 401


@app.get("/search")
def search():
    q = request.args.get("q", "")

    if len(q) > 64 or any(x in q for x in "'\";\\"):
        logging.warning("Rejected search input: %r", q)
        abort(400, description="Некорректный запрос")

    with db() as conn:
        rows = conn.execute(
            "SELECT title, price FROM items WHERE title LIKE ?",
            (f"%{q}%",)
        ).fetchall()

    result = "\n".join(
        f"{row['title']} - {row['price']}" for row in rows
    )

    return render_template_string(TPL, result=result)


if __name__ == "__main__":
    if not DB.exists():
        with sqlite3.connect(DB) as conn:
            conn.executescript(
                Path(__file__).with_name("init_db.sql").read_text()
            )

    app.run(host="127.0.0.1", port=5000, debug=False)
