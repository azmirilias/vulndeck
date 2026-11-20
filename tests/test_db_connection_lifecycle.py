import sqlite3
from tempfile import TemporaryDirectory
import unittest

from app import db


class DbConnectionLifecycleTests(unittest.TestCase):
    def test_context_manager_closes_connection(self):
        with TemporaryDirectory() as tmp:
            old_db_path = db.DB_PATH
            db.DB_PATH = f"{tmp}/test.db"
            try:
                with db.connect() as conn:
                    conn.execute("SELECT 1")
                with self.assertRaises(sqlite3.ProgrammingError):
                    conn.execute("SELECT 1")
            finally:
                db.DB_PATH = old_db_path


if __name__ == "__main__":
    unittest.main()
