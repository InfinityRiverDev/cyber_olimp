from sqlalchemy import create_engine, text

engine = create_engine("sqlite:///shop.db")


def find_user(login_value, password):
    query = text("""
        SELECT id, username, role
        FROM users
        WHERE username = :login
        AND password_hash = :password
    """)

    with engine.connect() as conn:
        return conn.execute(
            query,
            {
                "login": login_value,
                "password": password
            }
        ).fetchone()


def search_items(search_text):
    query = text("""
        SELECT title, price
        FROM items
        WHERE title LIKE :pattern
    """)

    with engine.connect() as conn:
        return conn.execute(
            query,
            {"pattern": f"%{search_text}%"}
        ).fetchall()


if __name__ == "__main__":
    print(find_user("admin", "test"))
    print(search_items("USB"))
