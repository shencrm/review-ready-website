
import React from 'react';
import { Smartphone, Shield, Bug, Terminal } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const IOSSection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div className="mb-8">
        <h2 className="text-3xl font-bold mb-6 flex items-center gap-2">
          <Smartphone className="text-cybr-primary" />
          iOS Penetration Testing
        </h2>
        <p className="mb-4">
          iOS's security architecture presents unique challenges for penetration testers.
          Apple's walled garden approach requires specific testing techniques and tools.
        </p>
      </div>
      
      <div className="card mb-10">
        <h3 className="text-2xl font-bold mb-4">Key Areas to Focus</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Data Protection
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Keychain Usage</li>
              <li>Data Protection API</li>
              <li>Secure Enclave</li>
              <li>App Sandbox</li>
            </ul>
            <p className="mt-2 text-sm">
              iOS provides multiple layers of data protection that should be properly implemented.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Local Storage
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>NSUserDefaults</li>
              <li>Core Data</li>
              <li>SQLite Databases</li>
              <li>Plist Files</li>
            </ul>
            <p className="mt-2 text-sm">
              Many iOS apps store sensitive data insecurely in local storage.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              App Transport Security
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>ATS exceptions</li>
              <li>Certificate validation</li>
              <li>Certificate pinning</li>
            </ul>
            <p className="mt-2 text-sm">
              App Transport Security (ATS) exceptions often introduce security risks.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              App Extensions
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Shared containers</li>
              <li>URL schemes</li>
              <li>Universal links</li>
            </ul>
            <p className="mt-2 text-sm">
              iOS app extensions can introduce security risks through data sharing mechanisms.
            </p>
          </div>
        </div>
      </div>
      
      <div className="mb-10">
        <h3 className="text-2xl font-bold mb-6">iOS Security Testing Process</h3>
        
        <div className="space-y-6">
          <div className="card">
            <h4 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Terminal className="text-cybr-primary h-5 w-5" />
              Setting Up the Testing Environment
            </h4>
            <p className="mb-3">
              Prepare a jailbroken device or suitable simulator for comprehensive iOS app testing:
            </p>
            <ul className="list-disc pl-6 space-y-1">
              <li>Jailbroken iOS device (preferred) or simulator</li>
              <li>Configure proxy tools (Burp Suite, Charles Proxy)</li>
              <li>Install reverse engineering tools (Hopper, Ghidra)</li>
              <li>Set up dynamic analysis tools (Frida, Objection)</li>
              <li>Install SSL kill switch for SSL pinning bypass</li>
            </ul>
          </div>
          
          <div className="card">
            <h4 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Terminal className="text-cybr-primary h-5 w-5" />
              IPA Analysis
            </h4>
            <p className="mb-3">Extract and analyze the iOS application binary:</p>
            
            <CodeExample
              language="bash"
              code={`# Extract IPA contents
unzip target_app.ipa -d extracted_ipa

# Decrypt the binary (if needed, using Clutch on jailbroken device)
./Clutch -d com.target.app

# Analyze binary with Hopper or class-dump
class-dump -H ./Target.app/Target -o ./headers

# Examine Info.plist for URL schemes, entitlements
plutil -p ./extracted_ipa/Info.plist`}
              title="Basic IPA Analysis Commands"
            />
            
            <p className="mt-4 mb-3">Examine the Info.plist file for:</p>
            <ul className="list-disc pl-6 space-y-1">
              <li>URL schemes</li>
              <li>ATS exceptions</li>
              <li>Background modes</li>
              <li>Entitlements</li>
              <li>App permissions</li>
            </ul>
          </div>
          
          <div className="card">
            <h4 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Terminal className="text-cybr-primary h-5 w-5" />
              Runtime Analysis with Objection
            </h4>
            <p className="mb-3">Use Objection for dynamic analysis of iOS applications:</p>
            
            <CodeExample
              language="bash"
              code={`# Launch the app with objection
objection --gadget "com.target.app" explore

# Explore iOS keychain items
ios keychain dump

# Disable SSL pinning
ios sslpinning disable

# Explore filesystem
env

# Check for jailbreak detection
ios jailbreak disable

# Monitor crypto operations
ios hooking watch class JRSCryptoManager`}
              title="Basic Objection Commands for iOS Analysis"
            />
          </div>
          
          <div className="card">
            <h4 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Shield className="text-cybr-primary h-5 w-5" />
              Common iOS Vulnerabilities
            </h4>
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Insecure Data Storage</strong>: Check for sensitive data in NSUserDefaults, plist files, or unprotected databases</li>
              <li><strong>Weak Keychain Configuration</strong>: Test for improper keychain access control settings</li>
              <li><strong>Clipboard Vulnerabilities</strong>: Check if sensitive data is accessible via the clipboard</li>
              <li><strong>URL Scheme Injection</strong>: Test for vulnerable URL scheme handlers that accept untrusted input</li>
              <li><strong>Jailbreak Detection Bypass</strong>: Attempt to circumvent jailbreak detection mechanisms</li>
              <li><strong>Insecure API Communication</strong>: Look for ATS exceptions that weaken transport security</li>
            </ul>
          </div>
        </div>
      </div>
      
      <div className="card">
        <h3 className="text-2xl font-bold mb-4">iOS-Specific Remediation Strategies</h3>
        <div className="space-y-4">
          <div>
            <h4 className="text-lg font-semibold">Secure Keychain Usage</h4>
            <CodeExample
              language="swift"
              code={`// Secure way to store data in the keychain
func saveToKeychain(key: String, data: Data) -> OSStatus {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAttrAccessControl as String: SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            nil
        )!
    ]
    
    // Delete any existing item first
    SecItemDelete(query as CFDictionary)
    
    // Add the new item
    return SecItemAdd(query as CFDictionary, nil)
}`}
              title="Secure Keychain Implementation"
              isVulnerable={false}
            />
          </div>
          
          <div>
            <h4 className="text-lg font-semibold">Certificate Pinning Implementation</h4>
            <CodeExample
              language="swift"
              code={`class NetworkManager: NSObject, URLSessionDelegate {
    // Store the certificate data for validation
    let pinnedCertificateData: [Data] = {
        let url = Bundle.main.url(forResource: "cert", withExtension: "der")!
        let data = try! Data(contentsOf: url)
        return [data]
    }()
    
    func urlSession(_ session: URLSession, 
                   didReceive challenge: URLAuthenticationChallenge, 
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // Check if this is a server trust challenge
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let serverTrust = challenge.protectionSpace.serverTrust {
            
            // Get certificate from the server
            if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {
                let serverCertificateData = SecCertificateCopyData(serverCertificate) as Data
                
                // Check if the certificate matches our pinned certificate
                if pinnedCertificateData.contains(serverCertificateData) {
                    let credential = URLCredential(trust: serverTrust)
                    completionHandler(.useCredential, credential)
                    return
                }
            }
            
            // Certificate didn't match
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Not a server trust challenge
        completionHandler(.performDefaultHandling, nil)
    }
}`}
              title="Certificate Pinning Implementation"
              isVulnerable={false}
            />
          </div>
        </div>
      </div>
    </section>
  );
};

export default IOSSection;
