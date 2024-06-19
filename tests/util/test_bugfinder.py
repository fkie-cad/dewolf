import sqlite3
from pathlib import Path

import pytest
from decompiler.util.bugfinder.bugfinder import DBConnector, store_reports_from_sample


@pytest.fixture
def temp_sqlite_db(tmp_path):
    """Fixture for creating a temporary SQLite database."""
    db_file = tmp_path / "temp.db"
    return db_file


@pytest.fixture
def test_sample():
    """Fixture for providing a test sample."""
    return Path("tests/samples/others/hello-world")


def verify_database_contents(db_file):
    """Check if bugfinder did write into SQLite file."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM dewolf")
    results = cursor.fetchall()
    assert len(results) > 0, "bugfinder did not write into database"
    assert "Hello, World!" in str(results)  # maybe this check is too brittle...
    conn.close()


def test_store_reports_from_sample(test_sample, temp_sqlite_db):
    """
    Integration test for bugfinder.py:
    Call bugfinder script on hello-world sample, and see
    if decompilation (attempts) are written to a temp database file.
    """
    with DBConnector(temp_sqlite_db) as db_reports:
        store_reports_from_sample(test_sample, db_reports, max_size=5)
    verify_database_contents(temp_sqlite_db)
