import os
import sqlite3
import redis
import json
import logging
import time
import requests
from flask import Flask, request, jsonify, g

# Initialize Flask app
app = Flask(__name__)

# Configuration
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
DATABASE_FILE = '/app/database.db'
LOG_FILE = '/var/log/securisphere/api_server.log'

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
                print(f"[API-SERVER] Redis connected at {REDIS_HOST}:{REDIS_PORT}")
                return
        except redis.ConnectionError:
            print(f"[API-SERVER] Redis connection attempt {i+1} failed. Retrying in 2s...")
            time.sleep(2)
    
    print("[API-SERVER] WARNING: Redis unavailable. Logging to file only.")
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
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create Products Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            description TEXT,
            category TEXT,
            stock INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Check if data exists
    cursor.execute('SELECT count(*) FROM users')
    if cursor.fetchone()[0] == 0:
        # Seed Users
        users = [
            ('admin', 'admin123', 'admin@securisphere.local', 'admin'),
            ('john', 'password123', 'john@company.com', 'user'),
            ('jane', 'jane2024', 'jane@company.com', 'user'),
            ('bob', 'bobsecure', 'bob@company.com', 'user'),
            ('alice', 'alice789', 'alice@company.com', 'user'),
            ('testuser', 'test123', 'test@company.com', 'user')
        ]
        cursor.executemany('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)', users)
        
        # Seed Products
        products = [
            ('Laptop Pro 15', 1299.99, 'High performance laptop with 16GB RAM', 'Electronics', 50),
            ('Smartphone X', 899.99, 'Latest flagship smartphone with 5G', 'Electronics', 120),
            ('Wireless Headphones', 199.99, 'Noise cancelling bluetooth headphones', 'Audio', 200),
            ('Tablet Air', 599.99, 'Lightweight tablet for professionals', 'Electronics', 75),
            ('Smart Watch', 349.99, 'Fitness tracking smartwatch', 'Wearables', 150),
            ('USB-C Hub', 49.99, '7-in-1 USB-C hub adapter', 'Accessories', 300),
            ('Mechanical Keyboard', 129.99, 'RGB mechanical gaming keyboard', 'Peripherals', 180),
            ('4K Monitor', 449.99, '27 inch 4K IPS display', 'Displays', 60),
            ('External SSD', 89.99, '1TB portable SSD USB 3.2', 'Storage', 250),
            ('Webcam HD', 79.99, '1080p webcam with microphone', 'Peripherals', 400)
        ]
        cursor.executemany('INSERT INTO products (name, price, description, category, stock) VALUES (?, ?, ?, ?, ?)', products)
        
        conn.commit()
        print(f"[API-SERVER] Database initialized with {len(users)} users and {len(products)} products")
    
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# Helper for Redis publishing
def publish_log(channel, data):
    if redis_available and redis_client:
        try:
            redis_client.publish(channel, json.dumps(data))
        except Exception as e:
            logger.error(f"Failed to publish to Redis: {e}")

# Middleware
@app.before_request
def log_request():
    g.start_time = time.time()
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    client_ip = request.remote_addr
    method = request.method
    path = request.path
    args = dict(request.args)
    logger.info(f"{timestamp} | REQUEST | {method} {path} | IP: {client_ip} | Params: {args}")

@app.after_request
def log_response(response):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    client_ip = request.remote_addr
    method = request.method
    path = request.path
    status_code = response.status_code
    logger.info(f"{timestamp} | RESPONSE | {method} {path} | Status: {status_code} | IP: {client_ip}")
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
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "api-server",
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S')
    })

# 2. List Products (Safe)
@app.route('/api/products', methods=['GET'])
def list_products():
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()
    
    product_list = [dict(p) for p in products]
    
    logger.info(f"API_REQUEST|list_products|{request.remote_addr}|{time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    return jsonify({
        "status": "success",
        "count": len(product_list),
        "products": product_list
    })

# 3. Search Products (VULNERABLE: SQL Injection)
@app.route('/api/products/search', methods=['GET'])
def search_products():
    query = request.args.get('q', '')
    client_ip = request.remote_addr
    timestamp = time.strftime('%Y-%m-%dT%H:%M:%S')
    
    # VULNERABLE: Intentional SQL injection for SecuriSphere demo
    # The query parameter must be directly concatenated into the SQL string.
    sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
    
    try:
        conn = get_db_connection()
        products = conn.execute(sql).fetchall() # Vulnerable execution
        conn.close()
        
        results = [dict(p) for p in products]
        
        logger.info(f"API_REQUEST|search|{client_ip}|q={query}|{timestamp}")
        
        publish_log("api_logs", {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "endpoint": "/api/products/search",
            "method": "GET",
            "params": {"q": query},
            "status_code": 200
        })
        
        return jsonify({
            "status": "success",
            "query": query,
            "count": len(results),
            "results": results
        })
        
    except Exception as e:
        logger.error(f"SQL Error: {str(e)}")
        publish_log("api_logs", {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "endpoint": "/api/products/search",
            "method": "GET",
            "params": {"q": query},
            "status_code": 500,
            "error": str(e)
        })
        return jsonify({"status": "error", "message": str(e)}), 500

# 4. Get Product by ID (Safe)
@app.route('/api/products/<int:id>', methods=['GET'])
def get_product(id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (id,)).fetchone()
    conn.close()
    
    logger.info(f"API_REQUEST|get_product|{request.remote_addr}|id={id}|{time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    if product:
        return jsonify({"status": "success", "product": dict(product)})
    else:
        return jsonify({"status": "error", "message": "Product not found"}), 404

# 5. Read File (VULNERABLE: Path Traversal)
@app.route('/api/files', methods=['GET'])
def read_file():
    filename = request.args.get('name', '')
    client_ip = request.remote_addr
    timestamp = time.strftime('%Y-%m-%dT%H:%M:%S')
    
    # VULNERABLE: Intentional path traversal for SecuriSphere demo
    filepath = f"/app/public/{filename}"
    
    try:
        # Do NOT check for ../ sequences
        with open(filepath, 'r') as f:
            content = f.read()
            
        logger.info(f"API_REQUEST|file_access|{client_ip}|file={filename}|{timestamp}")
        
        publish_log("api_logs", {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "endpoint": "/api/files",
            "method": "GET",
            "params": {"name": filename},
            "status_code": 200
        })
        
        return jsonify({"status": "success", "filename": filename, "content": content})
        
    except FileNotFoundError:
        publish_log("api_logs", {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "endpoint": "/api/files",
            "method": "GET",
            "params": {"name": filename},
            "status_code": 404
        })
        return jsonify({"status": "error", "message": "File not found"}), 404
    except PermissionError:
        publish_log("api_logs", {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "endpoint": "/api/files",
            "method": "GET",
            "params": {"name": filename},
            "status_code": 403
        })
        return jsonify({"status": "error", "message": "Permission denied"}), 403
    except Exception as e:
        publish_log("api_logs", {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "endpoint": "/api/files",
            "method": "GET",
            "params": {"name": filename},
            "status_code": 500
        })
        return jsonify({"status": "error", "message": str(e)}), 500

# 6. List Users (Safe - but exposes data)
@app.route('/api/users', methods=['GET'])
def list_users():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, email, role FROM users').fetchall()
    conn.close()
    
    user_list = [dict(u) for u in users]
    
    logger.info(f"API_REQUEST|list_users|{request.remote_addr}|{time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    return jsonify({
        "status": "success", 
        "count": len(user_list), 
        "users": user_list
    })

# 7. Get User by ID (Safe)
@app.route('/api/users/<int:id>', methods=['GET'])
def get_user(id):
    conn = get_db_connection()
    user = conn.execute('SELECT id, username, email, role FROM users WHERE id = ?', (id,)).fetchone()
    conn.close()
    
    logger.info(f"API_REQUEST|get_user|{request.remote_addr}|id={id}|{time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    if user:
        return jsonify({"status": "success", "user": dict(user)})
    else:
        return jsonify({"status": "error", "message": "User not found"}), 404

# 8. Admin Config (VULNERABLE: No Auth)
@app.route('/api/admin/config', methods=['GET'])
def get_admin_config():
    client_ip = request.remote_addr
    timestamp = time.strftime('%Y-%m-%dT%H:%M:%S')
    
    # VULNERABLE: No authentication check - intentional for demo
    logger.info(f"API_REQUEST|admin_config|{client_ip}|SENSITIVE_ACCESS|{timestamp}")
    
    publish_log("api_logs", {
        "timestamp": timestamp,
        "source_ip": client_ip,
        "endpoint": "/api/admin/config",
        "method": "GET",
        "params": {},
        "status_code": 200,
        "sensitive": True
    })
    
    return jsonify({
        "status": "success", 
        "config": {
            "db_host": "internal-db.securisphere.local", 
            "db_port": 5432, 
            "api_key": "sk-demo-secret-key-98765", 
            "debug_mode": True, 
            "allowed_origins": ["*"], 
            "max_upload_size": "50MB"
        }
    })

# 9. Create User
@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Request body must be JSON"}), 400
        
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or len(username) < 3:
        return jsonify({"status": "error", "message": "Username required (min 3 chars)"}), 400
    if not password or len(password) < 3:
        return jsonify({"status": "error", "message": "Password required (min 3 chars)"}), 400
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            (username, password, email)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        logger.info(f"API_REQUEST|create_user|{request.remote_addr}|username={username}|{time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        return jsonify({
            "status": "success", 
            "message": "User created", 
            "user_id": user_id
        }), 201
        
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Username already exists"}), 409
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

# 10. Export Users (VULNERABLE: Data Exfiltration)
@app.route('/api/admin/users/export', methods=['GET'])
def export_users():
    client_ip = request.remote_addr
    timestamp = time.strftime('%Y-%m-%dT%H:%M:%S')
    
    # VULNERABLE: Exposes full user data without auth - intentional for demo
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    
    user_list = [dict(u) for u in users]
    
    logger.info(f"API_REQUEST|data_export|{client_ip}|BULK_EXPORT|records={len(user_list)}|{timestamp}")
    
    publish_log("api_logs", {
        "timestamp": timestamp,
        "source_ip": client_ip,
        "endpoint": "/api/admin/users/export",
        "method": "GET",
        "params": {},
        "status_code": 200,
        "sensitive": True,
        "records_exported": len(user_list)
    })
    
    return jsonify({
        "status": "success",
        "export_format": "json",
        "exported_at": timestamp,
        "record_count": len(user_list),
        "data": user_list
    })

if __name__ == '__main__':
    init_db()
    connect_redis()
    print("[API-SERVER] Running on port 5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
