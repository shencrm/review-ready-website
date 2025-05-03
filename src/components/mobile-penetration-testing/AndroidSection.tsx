
import React from 'react';
import { Android, Shield, Bug, Terminal } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const AndroidSection: React.FC = () => {
  return (
    <section className="space-y-12">
      <div className="mb-8">
        <h2 className="text-3xl font-bold mb-6 flex items-center gap-2">
          <Android className="text-cybr-primary" />
          Android Penetration Testing
        </h2>
        <p className="mb-4">
          Android's open architecture provides multiple attack surfaces for security testers.
          Understanding Android's security model is essential for comprehensive penetration testing.
        </p>
      </div>
      
      <div className="card mb-10">
        <h3 className="text-2xl font-bold mb-4">Key Areas to Focus</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Application Components
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Activities</li>
              <li>Services</li>
              <li>Broadcast Receivers</li>
              <li>Content Providers</li>
            </ul>
            <p className="mt-2 text-sm">
              Each component presents unique security challenges and potential entry points for attacks.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Storage Mechanisms
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Shared Preferences</li>
              <li>SQLite Databases</li>
              <li>Internal/External Storage</li>
              <li>Key-Value Backup</li>
            </ul>
            <p className="mt-2 text-sm">
              Insecure data storage is a common vulnerability in Android applications.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              Inter-Process Communication
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>Intent-based communication</li>
              <li>Binder IPC</li>
              <li>AIDL interfaces</li>
            </ul>
            <p className="mt-2 text-sm">
              Insecure IPC can lead to privilege escalation and data leakage.
            </p>
          </div>
          
          <div>
            <h4 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <Bug className="text-cybr-primary h-5 w-5" />
              WebView Vulnerabilities
            </h4>
            <ul className="list-disc pl-6 space-y-1">
              <li>JavaScript Interface attacks</li>
              <li>Local file access</li>
              <li>Certificate validation issues</li>
            </ul>
            <p className="mt-2 text-sm">
              WebViews often introduce significant security risks when improperly configured.
            </p>
          </div>
        </div>
      </div>
      
      <div className="mb-10">
        <h3 className="text-2xl font-bold mb-6">Android Security Testing Process</h3>
        
        <div className="space-y-6">
          <div className="card">
            <h4 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Terminal className="text-cybr-primary h-5 w-5" />
              Setting Up the Testing Environment
            </h4>
            <p className="mb-3">
              Prepare a robust testing environment with both emulators and physical devices to ensure comprehensive coverage.
            </p>
            <ul className="list-disc pl-6 space-y-1">
              <li>Install the Android SDK and platform tools</li>
              <li>Set up a rooted device or emulator</li>
              <li>Configure proxy tools (Burp Suite, OWASP ZAP)</li>
              <li>Install reverse engineering tools (Jadx, Apktool)</li>
              <li>Set up dynamic analysis tools (Frida, Objection)</li>
            </ul>
          </div>
          
          <div className="card">
            <h4 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Terminal className="text-cybr-primary h-5 w-5" />
              APK Analysis
            </h4>
            <p className="mb-3">Extract and analyze the Android package to identify potential issues:</p>
            
            <CodeExample
              language="bash"
              code={`# Extract APK contents
apktool d target_app.apk -o output_folder

# Decompile Java code
jadx -d jadx_output target_app.apk

# Check for hardcoded secrets
grep -r "api_key\\|password\\|secret\\|token" output_folder/`}
              title="Basic APK Analysis Commands"
            />
            
            <p className="mt-4 mb-3">Examine the AndroidManifest.xml file for:</p>
            <ul className="list-disc pl-6 space-y-1">
              <li>Exported components (activities, services, receivers, providers)</li>
              <li>Custom permissions</li>
              <li>Debug flags</li>
              <li>Backup settings</li>
              <li>Network security configuration</li>
            </ul>
          </div>
          
          <div className="card">
            <h4 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Terminal className="text-cybr-primary h-5 w-5" />
              Runtime Analysis with Frida
            </h4>
            <p className="mb-3">Use Frida for dynamic instrumentation and runtime manipulation:</p>
            
            <CodeExample
              language="javascript"
              code={`// Hook cryptographic functions
Java.perform(function() {
  var cipher = Java.use("javax.crypto.Cipher");
  
  cipher.doFinal.overload("[B").implementation = function(bytes) {
    console.log("[+] Cipher.doFinal([B]) called");
    var result = this.doFinal(bytes);
    console.log("Input: " + bytes);
    console.log("Output: " + result);
    return result;
  };
});`}
              title="Basic Frida Script for Crypto Monitoring"
            />
          </div>
          
          <div className="card">
            <h4 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Shield className="text-cybr-primary h-5 w-5" />
              Common Android Vulnerabilities
            </h4>
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Insecure Content Providers</strong>: Test for improper permissions on content URIs</li>
              <li><strong>Insecure Broadcast Receivers</strong>: Check for unprotected broadcast receivers that accept data from any app</li>
              <li><strong>Insecure Activities</strong>: Test for exported activities that fail to validate input or allow unauthorized access</li>
              <li><strong>Weak Cryptography</strong>: Identify usage of deprecated algorithms (MD5, SHA-1) or hardcoded encryption keys</li>
              <li><strong>Root Detection Bypass</strong>: Attempt to circumvent root detection mechanisms</li>
              <li><strong>Certificate Pinning Bypass</strong>: Try to bypass certificate pinning to intercept HTTPS traffic</li>
            </ul>
          </div>
        </div>
      </div>
      
      <div className="card">
        <h3 className="text-2xl font-bold mb-4">Android-Specific Remediation Strategies</h3>
        <div className="space-y-4">
          <div>
            <h4 className="text-lg font-semibold">Secure IPC Communication</h4>
            <CodeExample
              language="java"
              code={`// Verifying calling package in a content provider
@Override
public Cursor query(Uri uri, String[] projection, String selection,
        String[] selectionArgs, String sortOrder) {
    
    // Verify caller
    if (!isCallerAllowed()) {
        throw new SecurityException("Caller is not allowed to query data");
    }
    
    // Continue with query
    // ...
}

private boolean isCallerAllowed() {
    String[] packages = getContext().getPackageManager().getPackagesForUid(
            Binder.getCallingUid());
    
    // Only allow specific trusted packages
    for (String pkg : packages) {
        if (ALLOWED_PACKAGES.contains(pkg)) {
            return true;
        }
    }
    return false;
}`}
              title="Secure Content Provider Implementation"
              isVulnerable={false}
            />
          </div>
          
          <div>
            <h4 className="text-lg font-semibold">Secure Data Storage</h4>
            <CodeExample
              language="java"
              code={`// Using Android Keystore for secure key storage
try {
    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null);
    
    if (!keyStore.containsAlias("my_secure_key")) {
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                "my_secure_key",
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .build();
                
        KeyGenerator kg = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        kg.init(spec);
        kg.generateKey();
    }
} catch (Exception e) {
    Log.e("Security", "Error initializing AndroidKeyStore", e);
}`}
              title="Secure Key Storage with Android Keystore"
              isVulnerable={false}
            />
          </div>
        </div>
      </div>
    </section>
  );
};

export default AndroidSection;
