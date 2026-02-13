from flask import Flask, jsonify, request
import psycopg2
import os

app = Flask(__name__)

# Database Configuration
DB_HOST = os.getenv("POSTGRES_HOST", "database")
DB_NAME = os.getenv("POSTGRES_DB", "securisphere_db")
DB_USER = os.getenv("POSTGRES_USER", "securisphere_user")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "securisphere_pass_2024")

def get_db_connection():
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )
    return conn

@app.route('/')
def home():
    return jsonify({"status": "running", "service": "api-server"}), 200

@app.route('/users', methods=['GET'])
def get_users():
    # Vulnerable to SQL Injection
    user_id = request.args.get('id')
    conn = get_db_connection()
    cur = conn.cursor()
    
    if user_id:
        query = f"SELECT * FROM users WHERE id = {user_id}" # VULNERABLE
        try:
            cur.execute(query)
            users = cur.fetchall()
            return jsonify(users), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        cur.execute("SELECT * FROM users")
        users = cur.fetchall()
        return jsonify(users), 200

@app.route('/data/<int:file_id>', methods=['GET'])
def get_data(file_id):
    # Vulnerable to IDOR (Insecure Direct Object Reference)
    # No permission check
    return jsonify({"file_id": file_id, "content": "Sensitive data"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
