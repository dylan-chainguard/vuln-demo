"""
API Service - Python Flask with vulnerable dependencies
"""
from flask import Flask, jsonify, request
import psycopg2
import requests
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)

# Database connection
def get_db_connection():
    return psycopg2.connect(
        host="postgres",
        database="vulndb",
        user="vulnuser",
        password="vulnpass"
    )

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "api"})

@app.route('/api/data')
def get_data():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT version();')
        db_version = cur.fetchone()
        cur.close()
        conn.close()

        return jsonify({
            "message": "API Service",
            "timestamp": datetime.now().isoformat(),
            "database": str(db_version[0]) if db_version else "unknown"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/token', methods=['POST'])
def create_token():
    """Generate JWT token - using vulnerable jsonwebtoken patterns"""
    data = request.get_json()
    token = jwt.encode(
        {'user': data.get('user', 'guest'), 'exp': datetime.utcnow() + timedelta(hours=24)},
        'secret-key',
        algorithm='HS256'
    )
    return jsonify({"token": token})

@app.route('/api/fetch', methods=['POST'])
def fetch_url():
    """Fetch external URL - demonstrates SSRF vulnerability pattern"""
    data = request.get_json()
    url = data.get('url')
    try:
        # Intentionally vulnerable to SSRF
        response = requests.get(url, timeout=5)
        return jsonify({"status": response.status_code, "content_length": len(response.content)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
