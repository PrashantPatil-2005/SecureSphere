import psycopg2
import os

DB_HOST = "database"
DB_NAME = "securisphere_db"
DB_USER = "securisphere_user"
DB_PASS = "securisphere_pass_2024"

try:
    print(f"Connecting to {DB_HOST}...")
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )
    print("Connected!")
    cur = conn.cursor()
    
    print("Checking for 'users' table...")
    cur.execute("SELECT * FROM users LIMIT 1")
    rows = cur.fetchall()
    print(f"Rows found: {rows}")
    
except Exception as e:
    print(f"ERROR: {e}")
