import sqlite3

def create_database():
    connection = sqlite3.connect("sentinel.db")

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
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