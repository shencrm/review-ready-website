
import React from 'react';
import { Bug } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const RaceConditions: React.FC = () => {
  return (
    <section id="race" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Race Conditions</h3>
      <p className="mb-6">
        Race conditions occur when the behavior of a system depends on the sequence or timing of uncontrollable events.
        In web applications, these vulnerabilities arise when multiple concurrent requests interact with the same
        resource, potentially causing security issues or data corruption.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Example Attack</h4>
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable Code (TOCTOU)" 
        code={`// Time-of-check to time-of-use vulnerability
app.post('/api/withdraw', async (req, res) => {
  const { userId, amount } = req.body;
  
  // Time of check - Get current balance
  const account = await db.getUserAccount(userId);
  
  // Check if sufficient funds
  if (account.balance >= amount) {
    // Time of use - Update balance
    // Vulnerable to race condition: Multiple requests could pass the check
    // before any of them update the balance
    await db.updateUserBalance(userId, account.balance - amount);
    res.json({ success: true, newBalance: account.balance - amount });
  } else {
    res.status(400).json({ error: 'Insufficient funds' });
  }
});

/* 
  Attacker with $100 could send multiple simultaneous withdrawal requests 
  for $100 each. Each request would see $100 balance and approve the 
  transaction, allowing the attacker to withdraw more than their balance.
*/`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Secure Implementation" 
        code={`// Option 1: Using database transactions
app.post('/api/withdraw', async (req, res) => {
  const { userId, amount } = req.body;
  
  try {
    // Use a transaction to ensure atomicity
    const result = await db.transaction(async (trx) => {
      // Lock the row for update to prevent concurrent modifications
      const account = await trx('accounts')
        .where('userId', userId)
        .forUpdate() // This locks the row in most databases
        .first();
      
      if (!account) {
        throw new Error('Account not found');
      }
      
      if (account.balance < amount) {
        throw new Error('Insufficient funds');
      }
      
      const newBalance = account.balance - amount;
      
      // Update within the same transaction
      await trx('accounts')
        .where('userId', userId)
        .update({ balance: newBalance });
      
      return { newBalance };
    });
    
    res.json({ success: true, newBalance: result.newBalance });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Option 2: Using optimistic concurrency control
app.post('/api/withdraw-optimistic', async (req, res) => {
  const { userId, amount } = req.body;
  const maxRetries = 5;
  let retries = 0;
  
  while (retries < maxRetries) {
    try {
      // Get current account state with version number
      const account = await db.getUserAccount(userId);
      
      if (account.balance < amount) {
        return res.status(400).json({ error: 'Insufficient funds' });
      }
      
      const newBalance = account.balance - amount;
      
      // Try to update, but only if version hasn't changed
      const updated = await db.updateUserBalanceWithVersion(
        userId,
        newBalance,
        account.version,
        account.version + 1
      );
      
      if (updated) {
        return res.json({ success: true, newBalance });
      }
      
      // If update failed, version has changed, retry
      retries++;
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  }
  
  res.status(409).json({ error: 'Failed due to concurrent updates' });
});`} 
      />
    </section>
  );
};

export default RaceConditions;
