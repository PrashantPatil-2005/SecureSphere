from flask import Flask, jsonify, request
import jwt
import datetime
import os

app = Flask(__name__)
APP_SECRET = "super-secret-key"  # Weak secret

# Mock User Database
users = {
    "admin": "password123", # Weak password
    "user": "user123"
}

@app.route('/')
def home():
    return jsonify({"status": "running", "service": "auth-service"}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username in users and users[username] == password:
        token = jwt.encode({
            'user': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, APP_SECRET, algorithm="HS256")
        return jsonify({'token': token}), 200
    
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/register', methods=['POST'])
def register():
    # Vulnerable: No password complexity check
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username in users:
        return jsonify({'message': 'User already exists'}), 400
    
    users[username] = password
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/verify', methods=['POST'])
def verify():
    token = request.json.get('token')
    if not token:
        return jsonify({'message': 'Token is missing'}), 403
    
    try:
        data = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        return jsonify({'valid': True, 'user': data['user']}), 200
    except:
        return jsonify({'valid': False, 'message': 'Token is invalid'}), 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
