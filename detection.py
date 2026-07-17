from database import (
    count_recent_failed_attempts,
    count_recent_failed_attempts_by_ip,
    create_security_alert
)


def analyze_failed_login(username, ip_address):
    failed_attempts = count_recent_failed_attempts(username)

    if failed_attempts == 3:
        create_security_alert(
            "Potential Brute Force Attempt",
            "MEDIUM",
            f"Three failed login attempts detected for username "
            f"'{username}' within 10 minutes."
        )

    if failed_attempts == 5:
        create_security_alert(
            "Brute Force Attempt",
            "HIGH",
            f"Five failed login attempts detected for username "
            f"'{username}' within 10 minutes."
        )

    failed_ip_attempts = count_recent_failed_attempts_by_ip(ip_address)

    if failed_ip_attempts == 10:
        create_security_alert(
            "Suspicious IP Activity",
            "HIGH",
            f"Ten failed login attempts detected from IP address "
            f"'{ip_address}' within 10 minutes."
        )