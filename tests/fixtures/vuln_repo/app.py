import sqlite3

DB_PASSWORD = "supersecret123"

def find_user(user_input: str):
    conn = sqlite3.connect("db.sqlite")
    query = f"SELECT * FROM users WHERE email = '{user_input}'"
    return conn.execute(query).fetchall()
