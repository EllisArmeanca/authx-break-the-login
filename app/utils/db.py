import sqlite3


DATABASE_PATH = "instance/authx.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn
