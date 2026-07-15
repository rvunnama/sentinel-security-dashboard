import sqlite3

def create_database():
    with sqlite3.connect("sentinel.db", timeout=10) as connection:
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'OPEN'
            )
        """)

def add_user(username, password_hash):
    with sqlite3.connect("sentinel.db") as connection:
        cursor = connection.cursor()

        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )

def get_user_by_username(username):
    with sqlite3.connect("sentinel.db", timeout=10) as connection:
        cursor = connection.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()

        return user

def log_login_attempt(username, success, ip_address):
    with sqlite3.connect("sentinel.db", timeout=10) as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO login_attempts (username, success, ip_address)
            VALUES (?, ?, ?)
            """,
            (username, success, ip_address)
        )

def get_recent_login_attempts(limit=10):
    with sqlite3.connect("sentinel.db", timeout=10) as connection:
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

        return attempts

def count_recent_failed_attempts(username):
    with sqlite3.connect("sentinel.db", timeout=10) as connection:
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

        return count

def create_security_alert(alert_type, severity, description):
    with sqlite3.connect("sentinel.db", timeout=10) as connection:
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

def get_recent_security_alerts(limit=10, status=None, severity=None):
    with sqlite3.connect("sentinel.db", timeout=10) as connection:
        cursor = connection.cursor()

        query = """
            SELECT id, alert_type, severity, description, timestamp, status
            FROM security_alerts
            WHERE 1 = 1
        """

        parameters = []

        if status:
            query += " AND status = ?"
            parameters.append(status)

        if severity:
            query += " AND severity = ?"
            parameters.append(severity)

        query += " ORDER BY timestamp DESC LIMIT ?"
        parameters.append(limit)

        cursor.execute(query, parameters)

        return cursor.fetchall()

def get_dashboard_stats():
    with sqlite3.connect("sentinel.db", timeout=10) as connection:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM login_attempts
            WHERE success = 1
            AND timestamp >= datetime('now', '-24 hours')
        """)
        successful_logins = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*)
            FROM login_attempts
            WHERE success = 0
            AND timestamp >= datetime('now', '-24 hours')
        """)
        failed_logins = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*)
            FROM security_alerts
            WHERE timestamp >= datetime('now', '-24 hours')
        """)
        total_alerts = cursor.fetchone()[0]

        return {
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "total_alerts": total_alerts
        }

def count_recent_failed_attempts_by_ip(ip_address):
    with sqlite3.connect("sentinel.db", timeout=10) as connection:
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

        return count

def resolve_security_alert(alert_id):
    with sqlite3.connect("sentinel.db", timeout=10) as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE security_alerts
            SET status = 'RESOLVED'
            WHERE id = ?
            """,
            (alert_id,)
        )