import sqlite3

def create_database():
    connection = sqlite3.connect("sentinel.db", timeout=10)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
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
    connection = sqlite3.connect("sentinel.db", timeout=10)
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

def get_recent_login_attempts(limit=10):
    connection = sqlite3.connect("sentinel.db", timeout=10)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT username, success, timestamp, ip_address
        FROM login_attempts
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,)
    )

    attempts = cursor.fetchall()

    connection.close()

    return attempts

def count_recent_failed_attempts(username):
    connection = sqlite3.connect("sentinel.db", timeout=10)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM login_attempts
        WHERE username = ?
        AND success = 0
        AND timestamp >= datetime('now', '-10 minutes')
        """,
        (username,)
    )

    count = cursor.fetchone()[0]

    connection.close()

    return count

def create_security_alert(alert_type, severity, description):
    connection = sqlite3.connect("sentinel.db", timeout=10)
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO security_alerts (
            alert_type,
            severity,
            description
        )
        VALUES (?, ?, ?)
        """,
        (alert_type, severity, description)
    )

    connection.commit()
    connection.close()

def get_recent_security_alerts(limit=10):
    connection = sqlite3.connect("sentinel.db", timeout=10)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT alert_type, severity, description, timestamp
        FROM security_alerts
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,)
    )

    alerts = cursor.fetchall()

    connection.close()

    return alerts

def get_dashboard_stats():
    connection = sqlite3.connect("sentinel.db", timeout=10)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM login_attempts
        WHERE success = 1
    """)
    successful_logins = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM login_attempts
        WHERE success = 0
    """)
    failed_logins = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_alerts
    """)
    total_alerts = cursor.fetchone()[0]

    connection.close()

    return {
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "total_alerts": total_alerts
    }

def count_recent_failed_attempts_by_ip(ip_address):
    connection = sqlite3.connect("sentinel.db", timeout=10)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM login_attempts
        WHERE ip_address = ?
        AND success = 0
        AND timestamp >= datetime('now', '-10 minutes')
        """,
        (ip_address,)
    )

    count = cursor.fetchone()[0]

    connection.close()

    return count