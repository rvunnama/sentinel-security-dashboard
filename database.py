import sqlite3

def create_database():
    connection = sqlite3.connect("sentinel.db")

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            success INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()

def add_user(username, password_hash):
    connection = sqlite3.connect("sentinel.db")
    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash)
    )

    connection.commit()
    connection.close()

def get_user_by_username(username):
    connection = sqlite3.connect("sentinel.db")
    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    )

    user = cursor.fetchone()

    connection.close()

    return user

def log_login_attempt(username, success, ip_address):
    connection = sqlite3.connect("sentinel.db")
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO login_attempts (username, success, ip_address)
        VALUES (?, ?, ?)
        """,
        (username, success, ip_address)
    )

    connection.commit()
    connection.close()