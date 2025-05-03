
import React from 'react';
import { Code } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const PrototypePollution: React.FC = () => {
  return (
    <section id="prototype" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Prototype Pollution</h3>
      <p className="mb-6">
        Prototype pollution is a JavaScript vulnerability that occurs when an attacker is able to modify the 
        prototype of a base object, such as Object.prototype. This can lead to property injection in all objects, 
        potentially causing denial of service, remote code execution, or bypassing security mechanisms.
      </p>
      
      <h4 className="text-xl font-semibold mt-6 mb-3">How It Works</h4>
      <p className="mb-4">
        In JavaScript, all objects inherit properties from their prototype. If an attacker can modify the prototype
        (typically Object.prototype), they can inject properties that will be present on all objects, potentially
        affecting application logic and security.
      </p>
      
      <CodeExample 
        language="javascript" 
        isVulnerable={true}
        title="Vulnerable Merge Function" 
        code={`// Recursive merge function with prototype pollution vulnerability
function merge(target, source) {
  for (let key in source) {
    if (key in source && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Attacker input
const malicious = JSON.parse('{"__proto__": {"isAdmin": true}}');

// Merging malicious input with a target object
const user = { name: "John" };
merge(user, malicious);

// Now ALL objects in the application have isAdmin=true
console.log({}.isAdmin); // true - security bypass!
`} 
      />
      
      <CodeExample 
        language="javascript" 
        isVulnerable={false}
        title="Safe Implementation" 
        code={`// Method 1: Check for dangerous properties
function secureMerge(target, source) {
  for (let key in source) {
    // Skip __proto__ and constructor
    if (key === '__proto__' || key === 'constructor') {
      continue;
    }
    
    if (key in source && typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      secureMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Method 2: Use Object.create(null) for "clean" objects
function secureMergeV2(target, source) {
  // Create a clean object with no prototype
  const cleanSource = Object.create(null);
  
  // Copy properties from source to clean object
  Object.keys(source).forEach(key => {
    cleanSource[key] = source[key];
  });
  
  // Now use the clean object for merging
  for (let key in cleanSource) {
    if (typeof cleanSource[key] === 'object' && cleanSource[key] !== null) {
      if (!target[key]) target[key] = {};
      secureMergeV2(target[key], cleanSource[key]);
    } else {
      target[key] = cleanSource[key];
    }
  }
  return target;
}

// Method 3: Use Object.freeze to protect the prototype
Object.freeze(Object.prototype);
// This prevents modifications to the Object prototype globally`} 
      />
      
      <h4 className="text-xl font-semibold mt-6 mb-3">Prevention Techniques</h4>
      <ul className="list-disc pl-6 space-y-2">
        <li>Use Object.create(null) to create "dictionary" objects without a prototype</li>
        <li>Validate and sanitize JSON input, especially when used in recursive merges</li>
        <li>Use libraries with protection against prototype pollution</li>
        <li>Implement property filtering to block dangerous property names (__proto__, constructor)</li>
        <li>Object.freeze(Object.prototype) can prevent modifications but may break some applications</li>
      </ul>
    </section>
  );
};

export default PrototypePollution;
