
import { Challenge } from './challenge-types';

export const raceConditionChallenges: Challenge[] = [
  {
    id: 'race-condition-1',
    title: 'Race Condition in Account Balance Update',
    description: 'Review this Python code that updates a user account balance. Is it vulnerable to race conditions?',
    difficulty: 'hard',
    category: 'Race Conditions',
    languages: ['Python'],
    type: 'single',
    vulnerabilityType: 'Race Condition',
    code: `import sqlite3
from flask import Flask, request, jsonify

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
    
    # Get current balance
    cursor.execute('SELECT balance FROM accounts WHERE user_id = ?', (user_id,))
    account = cursor.fetchone()
    
    if not account:
        conn.close()
        return jsonify({'error': 'Account not found'}), 404
    
    current_balance = account['balance']
    
    # Check if enough balance
    if current_balance < amount:
        conn.close()
        return jsonify({'error': 'Insufficient funds'}), 400
    
    # Update balance
    new_balance = current_balance - amount
    cursor.execute(
        'UPDATE accounts SET balance = ? WHERE user_id = ?',
        (new_balance, user_id)
    )
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'new_balance': new_balance})

if __name__ == '__main__':
    app.run(debug=True)`,
    answer: false,
    explanation: "This code is vulnerable to race conditions because it uses a 'read-then-write' pattern without proper synchronization. If two withdrawal requests for the same account are processed simultaneously, both might read the same initial balance and both could succeed even if together they exceed the available funds. To fix this, use database transactions with the appropriate isolation level, or implement row-level locking. For example, use 'SELECT ... FOR UPDATE' to lock the row until the transaction completes."
  }
];
