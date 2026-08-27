from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import sqlite3
import json
import hmac
import hashlib
from datetime import datetime

app = Flask(__name__, template_folder='templates')
CORS(app)

DB_NAME = "bot_data.db"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        init_data = data.get('initData')
        
        if not init_data:
            return jsonify({'status': 'error', 'message': 'initData required'}), 400
        
        params = dict(pair.split('=') for pair in init_data.split('&'))
        received_hash = params.pop('hash', None)
        
        if not received_hash:
            return jsonify({'status': 'error', 'message': 'Invalid data'}), 401
        
        bot_token = os.environ.get('BOT_TOKEN', '8919933621:AAEvVwj3J8puGopS52G3-aW54YuHI3bnqso')
        secret_key = hashlib.sha256(bot_token.encode()).digest()
        data_string = '\n'.join([f"{k}={v}" for k, v in sorted(params.items())])
        computed_hash = hmac.new(secret_key, data_string.encode(), hashlib.sha256).hexdigest()
        
        if computed_hash != received_hash:
            return jsonify({'status': 'error', 'message': 'Invalid signature'}), 401
        
        user_data = json.loads(params.get('user', '{}'))
        user_id = user_data.get('id')
        
        if not user_id:
            return jsonify({'status': 'error', 'message': 'User ID not found'}), 400
        
        ip = request.remote_addr
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            ip = forwarded.split(',')[0].strip()
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            UPDATE users 
            SET ip_address = ?, registered = 1, registered_at = ?
            WHERE user_id = ?
        ''', (ip, now, user_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'ok',
            'message': 'Registration successful',
            'user_id': user_id,
            'ip': ip
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/check_ip', methods=['POST'])
def check_ip():
    try:
        data = request.get_json()
        user1_id = data.get('user1_id')
        user2_id = data.get('user2_id')
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute('SELECT ip_address FROM users WHERE user_id = ?', (user1_id,))
        row1 = cursor.fetchone()
        
        cursor.execute('SELECT ip_address FROM users WHERE user_id = ?', (user2_id,))
        row2 = cursor.fetchone()
        
        conn.close()
        
        ip1 = row1[0] if row1 else None
        ip2 = row2[0] if row2 else None
        
        return jsonify({
            'status': 'ok',
            'same_ip': ip1 == ip2 and ip1 is not None
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
