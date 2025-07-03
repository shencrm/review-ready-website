
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Terminal, Activity, Eye, Zap, Settings } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const AndroidDynamicAnalysis: React.FC = () => {
  return (
    <div className="space-y-6">
      <Card className="bg-cybr-card border-cybr-muted">
        <CardHeader>
          <CardTitle className="text-cybr-primary flex items-center gap-2">
            <Terminal className="h-6 w-6" />
            Dynamic Analysis - Runtime Instrumentation
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="frida-basics" className="w-full">
            <TabsList className="grid grid-cols-5 w-full mb-6">
              <TabsTrigger value="frida-basics">Frida Basics</TabsTrigger>
              <TabsTrigger value="api-hooking">API Hooking</TabsTrigger>
              <TabsTrigger value="memory-analysis">Memory Analysis</TabsTrigger>
              <TabsTrigger value="runtime-modification">Runtime Modification</TabsTrigger>
              <TabsTrigger value="advanced-techniques">Advanced Techniques</TabsTrigger>
            </TabsList>

            <TabsContent value="frida-basics" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Frida Fundamentals</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Basic Frida Operations</h4>
                <CodeExample
                  language="bash"
                  title="Frida Command Line Usage"
                  code={`# List running processes
frida-ps -U

# List installed applications
frida-ps -Uai

# Attach to running app
frida -U -n "com.example.app"

# Spawn and attach to app
frida -U -f "com.example.app" --no-pause

# Load script from file
frida -U -l script.js -f "com.example.app"

# Interactive REPL session
frida -U "com.example.app"

# Kill app after script execution
frida -U -f "com.example.app" --kill-on-exit`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Basic JavaScript Hooking</h4>
                <CodeExample
                  language="javascript"
                  title="Fundamental Frida Script Structure"
                  code={`// Wait for Java environment to be available
Java.perform(function() {
    console.log("[+] Starting hooks...");
    
    // Get class reference
    var MainActivity = Java.use("com.example.app.MainActivity");
    
    // Hook method
    MainActivity.onCreate.implementation = function(savedInstanceState) {
        console.log("[+] MainActivity.onCreate called");
        
        // Call original implementation
        this.onCreate(savedInstanceState);
    };
    
    // Hook overloaded method
    var AuthManager = Java.use("com.example.app.AuthManager");
    AuthManager.authenticate.overload('java.lang.String', 'java.lang.String').implementation = function(username, password) {
        console.log("[+] Authentication attempt:");
        console.log("    Username: " + username);
        console.log("    Password: " + password);
        
        // Call original and capture result
        var result = this.authenticate(username, password);
        console.log("    Result: " + result);
        
        return result;
    };
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Objection Framework</h4>
                <CodeExample
                  language="bash"
                  title="Objection Usage"
                  code={`# Start objection session
objection -g "com.example.app" explore

# Common objection commands
android hooking list classes
android hooking list class_methods "com.example.app.AuthManager"
android hooking watch class "com.example.app.AuthManager"

# SSL pinning bypass
android sslpinning disable

# File system operations
android file ls /data/data/com.example.app/

# Memory operations
memory list modules
memory dump all from_base

# Environment information
env`}
                />
              </div>
            </TabsContent>

            <TabsContent value="api-hooking" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Advanced API Hooking</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Cryptographic API Hooking</h4>
                <CodeExample
                  language="javascript"
                  title="Crypto API Monitoring"
                  code={`Java.perform(function() {
    // Hook Cipher operations
    var Cipher = Java.use("javax.crypto.Cipher");
    
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log("[+] Cipher.doFinal called");
        console.log("    Algorithm: " + this.getAlgorithm());
        console.log("    Input: " + bytesToHex(input));
        
        var result = this.doFinal(input);
        console.log("    Output: " + bytesToHex(result));
        
        return result;
    };
    
    // Hook key generation
    var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
    KeyGenerator.generateKey.implementation = function() {
        console.log("[+] Key generation:");
        console.log("    Algorithm: " + this.getAlgorithm());
        
        var key = this.generateKey();
        console.log("    Key: " + bytesToHex(key.getEncoded()));
        
        return key;
    };
    
    // Hook MessageDigest (hashing)
    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.digest.overload('[B').implementation = function(input) {
        console.log("[+] MessageDigest.digest called");
        console.log("    Algorithm: " + this.getAlgorithm());
        console.log("    Input: " + bytesToHex(input));
        
        var result = this.digest(input);
        console.log("    Hash: " + bytesToHex(result));
        
        return result;
    };
    
    function bytesToHex(bytes) {
        var hex = "";
        for (var i = 0; i < bytes.length; i++) {
            hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex;
    }
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Network API Hooking</h4>
                <CodeExample
                  language="javascript"
                  title="Network Traffic Monitoring"
                  code={`Java.perform(function() {
    // Hook OkHttp3 requests
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Request = Java.use("okhttp3.Request");
    
    // Hook URL connections
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function() {
        console.log("[+] URL.openConnection called");
        console.log("    URL: " + this.toString());
        
        return this.openConnection();
    };
    
    // Hook HTTP requests
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    HttpURLConnection.getResponseCode.implementation = function() {
        console.log("[+] HTTP Request:");
        console.log("    URL: " + this.getURL().toString());
        console.log("    Method: " + this.getRequestMethod());
        
        var responseCode = this.getResponseCode();
        console.log("    Response Code: " + responseCode);
        
        return responseCode;
    };
    
    // Hook Socket connections
    var Socket = Java.use("java.net.Socket");
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(endpoint, timeout) {
        console.log("[+] Socket connection:");
        console.log("    Endpoint: " + endpoint.toString());
        console.log("    Timeout: " + timeout);
        
        this.connect(endpoint, timeout);
    };
});`}
                />
              </div>
            </TabsContent>

            <TabsContent value="memory-analysis" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Memory Analysis and Manipulation</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Heap Analysis</h4>
                <CodeExample
                  language="javascript"
                  title="Memory Scanning and Analysis"
                  code={`Java.perform(function() {
    // Enumerate loaded classes
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes("com.example.app")) {
                console.log("[+] Found class: " + className);
            }
        },
        onComplete: function() {
            console.log("[+] Class enumeration complete");
        }
    });
    
    // Find instances of specific class
    Java.choose("com.example.app.User", {
        onMatch: function(instance) {
            console.log("[+] Found User instance:");
            console.log("    Username: " + instance.username.value);
            console.log("    Email: " + instance.email.value);
            
            // Modify instance
            instance.isAdmin.value = true;
            console.log("    Modified isAdmin to true");
        },
        onComplete: function() {
            console.log("[+] Instance search complete");
        }
    });
    
    // Memory scanning for strings
    function scanMemoryForString(searchString) {
        var ranges = Process.enumerateRanges('r--');
        ranges.forEach(function(range) {
            try {
                Memory.scan(range.base, range.size, searchString, {
                    onMatch: function(address, size) {
                        console.log("[+] Found '" + searchString + "' at: " + address);
                        
                        // Read surrounding context
                        var context = Memory.readUtf8String(address, 100);
                        console.log("    Context: " + context);
                    },
                    onComplete: function() {}
                });
            } catch(e) {
                // Skip unreadable regions
            }
        });
    }
    
    // Usage
    scanMemoryForString("password");
    scanMemoryForString("secret");
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Native Memory Analysis</h4>
                <CodeExample
                  language="javascript"
                  title="Native Code Hooking"
                  code={`// Hook native functions
var nativeLib = Module.findBaseAddress("libnative.so");
if (nativeLib) {
    console.log("[+] Found native library at: " + nativeLib);
    
    // Hook specific function
    var encryptFunction = Module.findExportByName("libnative.so", "encrypt");
    if (encryptFunction) {
        Interceptor.attach(encryptFunction, {
            onEnter: function(args) {
                console.log("[+] encrypt() called");
                console.log("    arg0: " + args[0]);
                console.log("    arg1: " + args[1]);
                
                // Read string from memory
                var inputString = Memory.readUtf8String(args[0]);
                console.log("    Input string: " + inputString);
            },
            onLeave: function(retval) {
                console.log("[+] encrypt() returning: " + retval);
            }
        });
    }
    
    // Hook malloc to track memory allocations
    var mallocPtr = Module.findExportByName("libc.so", "malloc");
    if (mallocPtr) {
        Interceptor.attach(mallocPtr, {
            onEnter: function(args) {
                this.size = args[0].toInt32();
            },
            onLeave: function(retval) {
                if (this.size > 1000) {  // Track large allocations
                    console.log("[+] Large malloc: " + this.size + " bytes at " + retval);
                }
            }
        });
    }
}

// Memory patching example
function patchMemory(address, newValue) {
    Memory.protect(address, 4, 'rwx');
    Memory.writeU32(address, newValue);
    console.log("[+] Patched memory at " + address + " with value " + newValue);
}`}
                />
              </div>
            </TabsContent>

            <TabsContent value="runtime-modification" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Runtime Behavior Modification</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Authentication Bypass</h4>
                <CodeExample
                  language="javascript"
                  title="Authentication and Authorization Bypass"
                  code={`Java.perform(function() {
    // Biometric authentication bypass
    var BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
    BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded.implementation = function(result) {
        console.log("[+] Biometric authentication bypassed");
        this.onAuthenticationSucceeded(result);
    };
    
    // PIN/Pattern bypass
    var PatternLockView = Java.use("android.widget.PatternLockView");
    if (PatternLockView) {
        PatternLockView.checkPattern.implementation = function(pattern) {
            console.log("[+] Pattern check bypassed");
            return true;  // Always return success
        };
    }
    
    // Root detection bypass
    var RootChecker = Java.use("com.example.app.security.RootChecker");
    if (RootChecker) {
        RootChecker.isRooted.implementation = function() {
            console.log("[+] Root detection bypassed");
            return false;  // Device is not rooted
        };
    }
    
    // Certificate pinning bypass
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    if (CertificatePinner) {
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] Certificate pinning bypassed for: " + hostname);
            // Don't call original method - bypass the check
        };
    }
    
    // Debugger detection bypass
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[+] Debugger detection bypassed");
        return false;
    };
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Business Logic Manipulation</h4>
                <CodeExample
                  language="javascript"
                  title="Business Logic Bypass"
                  code={`Java.perform(function() {
    // Subscription/Premium bypass
    var SubscriptionManager = Java.use("com.example.app.SubscriptionManager");
    if (SubscriptionManager) {
        SubscriptionManager.isPremiumUser.implementation = function() {
            console.log("[+] Premium check bypassed");
            return true;  // User is always premium
        };
        
        SubscriptionManager.hasValidSubscription.implementation = function() {
            console.log("[+] Subscription check bypassed");
            return true;
        };
    }
    
    // Payment validation bypass
    var PaymentValidator = Java.use("com.example.app.payment.PaymentValidator");
    if (PaymentValidator) {
        PaymentValidator.validatePayment.implementation = function(paymentInfo) {
            console.log("[+] Payment validation bypassed");
            console.log("    Original payment: " + paymentInfo.toString());
            
            // Always return successful payment
            var PaymentResult = Java.use("com.example.app.payment.PaymentResult");
            return PaymentResult.$new(true, "SUCCESS", "Payment bypassed");
        };
    }
    
    // Trial period manipulation
    var TrialManager = Java.use("com.example.app.TrialManager");
    if (TrialManager) {
        TrialManager.getDaysRemaining.implementation = function() {
            console.log("[+] Trial period extended");
            return 999;  // 999 days remaining
        };
        
        TrialManager.isTrialExpired.implementation = function() {
            console.log("[+] Trial expiration bypassed");
            return false;  // Trial never expires
        };
    }
    
    // Feature flag manipulation
    var FeatureManager = Java.use("com.example.app.FeatureManager");
    if (FeatureManager) {
        FeatureManager.isFeatureEnabled.implementation = function(featureName) {
            console.log("[+] Feature enabled: " + featureName);
            return true;  // All features enabled
        };
    }
});`}
                />
              </div>
            </TabsContent>

            <TabsContent value="advanced-techniques" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Advanced Dynamic Analysis</h3>
              
              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Anti-Analysis Evasion</h4>
                <CodeExample
                  language="javascript"
                  title="Advanced Evasion Techniques"
                  code={`Java.perform(function() {
    // Frida detection bypass
    var ActivityThread = Java.use("android.app.ActivityThread");
    ActivityThread.currentApplication.implementation = function() {
        var app = this.currentApplication();
        
        // Hide Frida from process name
        if (app) {
            var processName = app.getApplicationInfo().processName.value;
            if (processName.includes("frida") || processName.includes("gadget")) {
                console.log("[+] Hiding Frida from process detection");
                app.getApplicationInfo().processName.value = "com.example.app";
            }
        }
        
        return app;
    };
    
    // Hide Frida threads
    var Thread = Java.use("java.lang.Thread");
    Thread.getName.implementation = function() {
        var name = this.getName();
        if (name.includes("frida") || name.includes("gum")) {
            return "NormalThread";
        }
        return name;
    };
    
    // Emulator detection bypass
    var Build = Java.use("android.os.Build");
    Build.MANUFACTURER.value = "Samsung";
    Build.MODEL.value = "SM-G973F";
    Build.PRODUCT.value = "beyond1lte";
    Build.FINGERPRINT.value = "samsung/beyond1ltexx/beyond1lte:10/QP1A.190711.020/G973FXXU3BSL4:user/release-keys";
    
    // Mock hardware features
    var SystemProperties = Java.use("android.os.SystemProperties");
    SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
        if (key === "ro.kernel.qemu" || key === "ro.hardware") {
            return "real_hardware";
        }
        return this.get(key, def);
    };
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Advanced Monitoring</h4>
                <CodeExample
                  language="javascript"
                  title="Comprehensive Activity Monitoring"
                  code={`Java.perform(function() {
    // File system monitoring
    var FileInputStream = Java.use("java.io.FileInputStream");
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    
    FileInputStream.$init.overload('java.io.File').implementation = function(file) {
        console.log("[+] File read: " + file.getAbsolutePath());
        return this.$init(file);
    };
    
    FileOutputStream.$init.overload('java.io.File', 'boolean').implementation = function(file, append) {
        console.log("[+] File write: " + file.getAbsolutePath() + " (append: " + append + ")");
        return this.$init(file, append);
    };
    
    // Database operations monitoring
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
        console.log("[+] SQL executed: " + sql);
        return this.execSQL(sql);
    };
    
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, selectionArgs) {
        console.log("[+] SQL query: " + sql);
        if (selectionArgs) {
            for (var i = 0; i < selectionArgs.length; i++) {
                console.log("    Arg " + i + ": " + selectionArgs[i]);
            }
        }
        return this.rawQuery(sql, selectionArgs);
    };
    
    // Shared Preferences monitoring
    var SharedPreferences = Java.use("android.content.SharedPreferences");
    var Editor = Java.use("android.content.SharedPreferences$Editor");
    
    Editor.putString.implementation = function(key, value) {
        console.log("[+] SharedPreferences write: " + key + " = " + value);
        return this.putString(key, value);
    };
    
    SharedPreferences.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        console.log("[+] SharedPreferences read: " + key + " = " + value);
        return value;
    };
    
    // Intent monitoring
    var Intent = Java.use("android.content.Intent");
    Intent.putExtra.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
        console.log("[+] Intent extra: " + key + " = " + value);
        return this.putExtra(key, value);
    };
});`}
                />
              </div>
            </TabsContent>
          </Tabs>

          <div className="mt-6 p-4 bg-cybr-muted/20 rounded-lg">
            <h4 className="font-medium text-cybr-accent mb-2">Dynamic Analysis Best Practices</h4>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li>Start with basic hooks and gradually add complexity</li>
              <li>Always test hooks on multiple app versions</li>
              <li>Use try-catch blocks to handle runtime errors gracefully</li>
              <li>Log both input parameters and return values</li>
              <li>Create modular scripts for different testing scenarios</li>
              <li>Document all modifications and their purposes</li>
              <li>Test on both rooted and non-rooted devices when possible</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AndroidDynamicAnalysis;
