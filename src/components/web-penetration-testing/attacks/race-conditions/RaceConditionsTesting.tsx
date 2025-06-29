
import React from 'react';

const RaceConditionsTesting: React.FC = () => {
  return (
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
  );
};

export default RaceConditionsTesting;
