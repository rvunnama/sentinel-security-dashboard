import sqlite3
from datetime import datetime, timedelta
import os

DATABASE_PATH = os.environ.get("SENTINEL_DATABASE_PATH", "sentinel.db")

def create_database():
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                success INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT NOT NULL
            )
        """)

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
    with sqlite3.connect(DATABASE_PATH) as connection:
        cursor = connection.cursor()

        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )

def get_user_by_username(username):
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
        cursor = connection.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()

        return user

def log_login_attempt(username, success, ip_address):
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO login_attempts (username, success, ip_address)
            VALUES (?, ?, ?)
            """,
            (username, success, ip_address)
        )

def get_recent_login_attempts(limit=10):
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
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
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
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
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
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
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
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
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
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
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
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
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE security_alerts
            SET status = 'RESOLVED'
            WHERE id = ?
            """,
            (alert_id,)
        )

def get_login_activity_chart_data():
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                strftime('%Y-%m-%d %H:00', timestamp) AS hour,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END),
                SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END)
            FROM login_attempts
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour ASC
            """
        )

        rows = cursor.fetchall()

    activity_by_hour = {
        row[0]: {
            "successful": row[1],
            "failed": row[2]
        }
        for row in rows
    }

    now = datetime.utcnow().replace(
        minute=0,
        second=0,
        microsecond=0
    )

    labels = []
    successful = []
    failed = []

    for hours_ago in range(23, -1, -1):
        hour = now - timedelta(hours=hours_ago)
        database_hour = hour.strftime("%Y-%m-%d %H:00")
        display_hour = hour.strftime("%-I %p")

        labels.append(display_hour)

        data = activity_by_hour.get(
            database_hour,
            {"successful": 0, "failed": 0}
        )

        successful.append(data["successful"])
        failed.append(data["failed"])

    return labels, successful, failed

def get_current_threat_level():
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM security_alerts
            WHERE status = 'OPEN'
        """)

        open_alerts = cursor.fetchone()[0]

    if open_alerts == 0:
        return "LOW"

    elif open_alerts <= 2:
        return "MEDIUM"

    else:
        return "HIGH"

def get_top_targeted_usernames(limit=5):
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT username, COUNT(*) AS failed_attempts
            FROM login_attempts
            WHERE success = 0
            AND timestamp >= datetime('now', '-24 hours')
            GROUP BY username
            ORDER BY failed_attempts DESC
            LIMIT ?
            """,
            (limit,)
        )

        return cursor.fetchall()

def get_top_targeted_ip_addresses(limit=5):
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT ip_address, COUNT(*) AS failed_attempts
            FROM login_attempts
            WHERE success = 0
            AND timestamp >= datetime('now', '-24 hours')
            GROUP BY ip_address
            ORDER BY failed_attempts DESC
            LIMIT ?
            """,
            (limit,)
        )

        return cursor.fetchall()

def get_alert_severity_distribution():
    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT severity, COUNT(*) AS total
            FROM security_alerts
            GROUP BY severity
            ORDER BY total DESC
        """)

        rows = cursor.fetchall()

        labels = []
        counts = []

        for row in rows:
            labels.append(row[0])
            counts.append(row[1])

        return labels, counts

def has_successful_login_from_ip(username, ip_address):
    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT 1
        FROM login_attempts
        WHERE username = ?
          AND ip_address = ?
          AND success = 1
        LIMIT 1
        """,
        (username, ip_address)
    )

    result = cursor.fetchone()
    connection.close()

    return result is not None