
import React from 'react';
import { Bug } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';

const InsecureDeserialization: React.FC = () => {
  return (
    <section id="deserial" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Insecure Deserialization</h3>
      <p className="mb-6">
        Insecure deserialization occurs when an application deserializes untrusted data without sufficient verification,
        allowing attackers to manipulate serialized objects to achieve harmful results, including remote code execution.
        This vulnerability can lead to serious attacks like authentication bypass, privilege escalation, and injection attacks.
      </p>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <SecurityCard
          title="Immediate Impact"
          description="Remote code execution, application crashes, and complex replay attacks that bypass authentication and authorization."
          severity="high"
        />
        <SecurityCard
          title="Vulnerable Languages"
          description="Java, PHP, Python, and .NET are commonly affected due to their powerful serialization frameworks."
          severity="high"
        />
      </div>
      
      <CodeExample 
        language="php" 
        isVulnerable={true}
        title="Vulnerable PHP Deserialization" 
        code={`<?php
// Vulnerable code accepts serialized object from user
$userData = unserialize($_COOKIE['user_data']);

// Attacker-controlled cookie might contain:
// O:8:"UserInfo":2:{s:8:"username";s:5:"admin";s:5:"admin";b:1;}
// This could create an object with unauthorized admin privileges
?>`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Safe Alternative" 
        code={`// Use JSON instead of serialized objects
const userData = JSON.parse(cookie);

// Explicitly validate data after parsing
if (!isValidUserData(userData)) {
  throw new Error("Invalid user data");
}

// Explicitly set properties from the validated data
const user = {
  username: userData.username,
  // Don't directly copy admin flag from user input
};

// Check permissions through proper authorization system
const isAdmin = authorizationService.isAdmin(user.username);`} 
      />
    </section>
  );
};

export default InsecureDeserialization;
