import os
import tempfile
import unittest

os.environ["SENTINEL_DATABASE_PATH"] = tempfile.mktemp(
    prefix="sentinel_test_",
    suffix=".db"
)

import database


class DatabaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        database.create_database()

    @classmethod
    def tearDownClass(cls):
        test_database_path = os.environ["SENTINEL_DATABASE_PATH"]

        if os.path.exists(test_database_path):
            os.remove(test_database_path)

    def setUp(self):
        with database.sqlite3.connect(
            database.DATABASE_PATH,
            timeout=10
        ) as connection:
            cursor = connection.cursor()
            cursor.execute("DELETE FROM security_alerts")
            cursor.execute("DELETE FROM login_attempts")
            cursor.execute("DELETE FROM users")

    def test_add_and_retrieve_user(self):
        database.add_user("rishika", "hashed-password")

        user = database.get_user_by_username("rishika")

        self.assertIsNotNone(user)
        self.assertEqual(user[1], "rishika")
        self.assertEqual(user[2], "hashed-password")

    def test_duplicate_username_is_rejected(self):
        database.add_user("rishika", "first-hash")

        with self.assertRaises(database.sqlite3.IntegrityError):
            database.add_user("rishika", "second-hash")

    def test_login_attempt_is_recorded(self):
        database.log_login_attempt(
            "rishika",
            0,
            "127.0.0.1"
        )

        attempts = database.get_recent_login_attempts()

        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0][0], "rishika")
        self.assertEqual(attempts[0][1], 0)
        self.assertEqual(attempts[0][3], "127.0.0.1")

    def test_security_alert_can_be_resolved(self):
        database.create_security_alert(
            "Brute Force Attempt",
            "HIGH",
            "Test alert"
        )

        alerts = database.get_recent_security_alerts()
        alert_id = alerts[0][0]

        database.resolve_security_alert(alert_id)

        updated_alerts = database.get_recent_security_alerts()
        self.assertEqual(updated_alerts[0][5], "RESOLVED")


if __name__ == "__main__":
    unittest.main()