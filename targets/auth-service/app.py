import os
import sqlite3
import redis
import json
import logging
import time
import hashlib
from flask import Flask, request, jsonify, g

# Initialize Flask app
app = Flask(__name__)

# Configuration
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
DATABASE_FILE = '/app/auth.db'
LOG_FILE = '/var/log/securisphere/auth_service.log'

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE)
    ]
)
logger = logging.getLogger(__name__)

# Redis Connection
redis_client = None
redis_available = False

def connect_redis():
    global redis_client, redis_available
    for i in range(5):
        try:
            redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
            if redis_client.ping():
                redis_available = True
                print(f"[AUTH-SERVICE] Redis connected at {REDIS_HOST}:{REDIS_PORT}")
                return
        except redis.ConnectionError:
            print(f"[AUTH-SERVICE] Redis connection attempt {i+1} failed. Retrying in 2s...")
            time.sleep(2)
    
    print("[AUTH-SERVICE] WARNING: Redis unavailable. Logging to file only.")
    redis_available = False

# Database Setup
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Create Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            failed_attempts INTEGER DEFAULT 0,
            locked INTEGER DEFAULT 0,
            last_login TEXT,
            last_failed TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    ''')
    
    # Check if data exists
    cursor.execute('SELECT count(*) FROM users')
    if cursor.fetchone()[0] == 0:
        # Seed Users
        users = [
            ('admin', 'admin123', 'admin'),
            ('john', 'password123', 'user'),
            ('jane', 'jane2024', 'user'),
            ('bob', 'bobsecure', 'user'),
            ('alice', 'alice789', 'user'),
            ('testuser', 'test123', 'user')
        ]
        cursor.executemany('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', users)
        conn.commit()
        print(f"[AUTH-SERVICE] Database initialized with {len(users)} users")
    
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# Helper for Redis publishing
def publish_event(channel, data):
    if redis_available and redis_client:
        try:
            redis_client.publish(channel, json.dumps(data))
        except Exception as e:
            logger.error(f"Failed to publish to Redis: {e}")

# Middleware
@app.before_request
def log_request():
    g.start_time = time.time()
    logger.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | REQUEST | {request.method} {request.path} | IP: {request.remote_addr}")

@app.after_request
def log_response(response):
    logger.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | RESPONSE | {request.method} {request.path} | Status: {response.status_code} | IP: {request.remote_addr}")
    return response

# Error Handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({"status": "error", "message": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"status": "error", "message": "Internal server error"}), 500

# --- ENDPOINTS ---

# 1. Health Check
@app.route('/auth/status', methods=['GET'])
def health_check():
    try:
        conn = get_db_connection()
        total_users = conn.execute('SELECT count(*) FROM users').fetchone()[0]
        locked_accounts = conn.execute('SELECT count(*) FROM users WHERE locked = 1').fetchone()[0]
        conn.close()
    except:
        total_users = 0
        locked_accounts = 0

    return jsonify({
        "status": "running",
        "service": "auth-service",
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S'),
        "total_users": total_users,
        "locked_accounts": locked_accounts
    })

# 2. Login (Brute Force Tracking)
@app.route('/auth/login', methods=['POST'])
def login():
    client_ip = request.remote_addr
    timestamp = time.strftime('%Y-%m-%dT%H:%M:%S')
    
    # 1. Check JSON body
    if not request.is_json:
        return jsonify({"status": "error", "message": "Request body must be JSON with username and password"}), 400
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # 2 & 3. Validation
    if not username:
        return jsonify({"status": "error", "message": "Username is required"}), 400
    if not password:
        return jsonify({"status": "error", "message": "Password is required"}), 400
        
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    
    # 8. User does NOT exist
    if not user:
        conn.close()
        logger.info(f"AUTH|FAILURE|{client_ip}|{username}|unknown_username")
        
        publish_event("auth_events", {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "username": username,
            "event_type": "login_failure",
            "success": False,
            "details": {
                "reason": "unknown_username",
                "attempted_username": username
            }
        })
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    
    user_id = user['id']
    failed_attempts = user['failed_attempts']
    locked = user['locked']
    db_password = user['password']
    
    # 5. User exists AND locked
    if locked:
        conn.close()
        logger.info(f"AUTH|LOCKED|{client_ip}|{username}|account_locked")
        
        publish_event("auth_events", {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "username": username,
            "event_type": "login_locked_account",
            "success": False,
            "details": {
                "reason": "Account locked due to excessive failed attempts",
                "failed_attempts": failed_attempts
            }
        })
        return jsonify({
            "status": "error", 
            "message": "Account locked. Contact administrator.", 
            "locked": True, 
            "failed_attempts": failed_attempts
        }), 403
    
    # 6. User exists AND password matches
    if password == db_password:
        conn.execute('UPDATE users SET failed_attempts = 0, last_login = ? WHERE id = ?', (timestamp, user_id))
        conn.commit()
        conn.close()
        
        token = hashlib.sha256(f"{username}{timestamp}".encode()).hexdigest()[:32]
        
        logger.info(f"AUTH|SUCCESS|{client_ip}|{username}|login_success")
        
        publish_event("auth_events", {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "username": username,
            "event_type": "login_success",
            "success": True,
            "details": {
                "previous_failures": failed_attempts,
                "suspicious": failed_attempts >= 3
            }
        })
        
        return jsonify({
            "status": "success", 
            "message": "Login successful", 
            "user": {
                "id": user['id'], 
                "username": user['username'], 
                "role": user['role']
            }, 
            "token": token
        }), 200
        
    # 7. User exists AND password does NOT match
    else:
        new_failed_attempts = failed_attempts + 1
        new_locked = 1 if new_failed_attempts >= 5 else 0
        
        conn.execute(
            'UPDATE users SET failed_attempts = ?, locked = ?, last_failed = ? WHERE id = ?',
            (new_failed_attempts, new_locked, timestamp, user_id)
        )
        conn.commit()
        conn.close()
        
        logger.info(f"AUTH|FAILURE|{client_ip}|{username}|incorrect_password")
        
        publish_event("auth_events", {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "username": username,
            "event_type": "login_failure",
            "success": False,
            "details": {
                "failed_attempts": new_failed_attempts,
                "account_locked": bool(new_locked),
                "reason": "incorrect_password"
            }
        })
        
        if new_locked:
            logger.info(f"AUTH|LOCKOUT|{client_ip}|{username}|max_attempts_exceeded")
            publish_event("auth_events", {
                "timestamp": timestamp,
                "source_ip": client_ip,
                "username": username,
                "event_type": "account_lockout",
                "success": False,
                "details": {
                    "failed_attempts": new_failed_attempts,
                    "reason": "max_attempts_exceeded"
                }
            })
            
        remaining = 5 - new_failed_attempts
        if remaining < 0: remaining = 0
            
        return jsonify({
            "status": "error", 
            "message": "Invalid credentials", 
            "attempts_remaining": remaining
        }), 401

# 3. Reset Account
@app.route('/auth/reset/<username>', methods=['POST'])
def reset_account(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    
    if user:
        conn.execute('UPDATE users SET failed_attempts = 0, locked = 0 WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        
        logger.info(f"AUTH|RESET|{request.remote_addr}|{username}")
        
        return jsonify({
            "status": "success", 
            "message": f"Account '{username}' has been reset", 
            "username": username
        })
    else:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404

# 4. Reset All Accounts
@app.route('/auth/reset-all', methods=['POST'])
def reset_all_accounts():
    conn = get_db_connection()
    result = conn.execute('UPDATE users SET failed_attempts = 0, locked = 0')
    conn.commit()
    count = result.rowcount
    conn.close()
    
    logger.info(f"AUTH|RESET_ALL|{request.remote_addr}|accounts={count}")
    
    return jsonify({
        "status": "success", 
        "message": "All accounts have been reset", 
        "accounts_reset": count
    })

# 5. List Users with Lock Status
@app.route('/auth/users', methods=['GET'])
def list_users():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, role, failed_attempts, locked, last_login, last_failed FROM users').fetchall()
    conn.close()
    
    user_list = [dict(u) for u in users]
    # Convert locked to bool
    for u in user_list:
        u['locked'] = bool(u['locked'])
        
    return jsonify({"status": "success", "users": user_list})

if __name__ == '__main__':
    init_db()
    connect_redis()
    print("[AUTH-SERVICE] Running on port 5001")
    app.run(host='0.0.0.0', port=5001, debug=False)
