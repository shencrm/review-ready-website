
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Database, HardDrive, Lock, FileText, Shield, Key } from 'lucide-react';
import CodeExample from '@/components/CodeExample';

const AndroidStorageAnalysis: React.FC = () => {
  return (
    <div className="space-y-6">
      <Card className="bg-cybr-card border-cybr-muted">
        <CardHeader>
          <CardTitle className="text-cybr-primary flex items-center gap-2">
            <Database className="h-6 w-6" />
            Android Storage Security Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="mb-6 p-4 bg-cybr-muted/20 rounded-lg">
            <p className="text-cybr-foreground">
              Android storage security is critical for protecting sensitive user data. This comprehensive analysis covers 
              all storage mechanisms including SharedPreferences, SQLite databases, internal/external storage, and the 
              Android Keystore. Understanding storage vulnerabilities is essential for identifying data exposure risks, 
              improper encryption implementation, and insecure data persistence patterns in Android applications.
            </p>
          </div>

          <Tabs defaultValue="shared-preferences" className="w-full">
            <TabsList className="grid grid-cols-6 w-full mb-6">
              <TabsTrigger value="shared-preferences">SharedPreferences</TabsTrigger>
              <TabsTrigger value="sqlite-analysis">SQLite Analysis</TabsTrigger>
              <TabsTrigger value="file-storage">File Storage</TabsTrigger>
              <TabsTrigger value="keystore-analysis">Keystore Analysis</TabsTrigger>
              <TabsTrigger value="external-storage">External Storage</TabsTrigger>
              <TabsTrigger value="backup-analysis">Backup Analysis</TabsTrigger>
            </TabsList>

            <TabsContent value="shared-preferences" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">SharedPreferences Security Testing</h3>
              <p className="text-cybr-foreground/80 mb-4">
                SharedPreferences is commonly used for storing application settings and small pieces of data. 
                However, it's frequently misused for storing sensitive information without proper encryption, 
                making it a prime target for security testing.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Locating SharedPreferences Files</h4>
                <CodeExample
                  language="bash"
                  title="Finding and Analyzing SharedPreferences"
                  code={`# Locate SharedPreferences files
adb shell "find /data/data/com.example.app -name '*.xml' -type f"
adb shell "ls -la /data/data/com.example.app/shared_prefs/"

# Pull all SharedPreferences files
adb pull /data/data/com.example.app/shared_prefs/ ./shared_prefs/

# Analyze content for sensitive data
grep -r "password\\|secret\\|token\\|key\\|credit" ./shared_prefs/
grep -r "api_key\\|auth\\|session\\|pin\\|fingerprint" ./shared_prefs/

# Check for Base64 encoded data
grep -r "^[A-Za-z0-9+/]*={0,2}$" ./shared_prefs/ | base64 -d

# Look for encrypted values patterns
grep -r "encrypted\\|cipher\\|aes\\|des" ./shared_prefs/

# Check for JSON structures in preferences
grep -r "{.*}" ./shared_prefs/ | python -m json.tool`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Dynamic SharedPreferences Analysis</h4>
                <CodeExample
                  language="javascript"
                  title="Frida Script for SharedPreferences Hooking"
                  code={`Java.perform(function() {
    console.log("[+] SharedPreferences Analysis Started");
    
    // Hook SharedPreferences.Editor methods
    var SharedPreferencesEditor = Java.use("android.content.SharedPreferences$Editor");
    
    // Hook putString
    SharedPreferencesEditor.putString.implementation = function(key, value) {
        console.log("[+] SharedPreferences.putString()");
        console.log("    Key: " + key);
        console.log("    Value: " + value);
        
        // Check for sensitive patterns
        var sensitivePatterns = [
            /password/i, /secret/i, /token/i, /key/i, 
            /auth/i, /session/i, /pin/i, /credit/i
        ];
        
        for (var i = 0; i < sensitivePatterns.length; i++) {
            if (key.match(sensitivePatterns[i]) || value.match(sensitivePatterns[i])) {
                console.log("[!] SENSITIVE DATA DETECTED in SharedPreferences");
                console.log("    Pattern: " + sensitivePatterns[i]);
                break;
            }
        }
        
        return this.putString(key, value);
    };
    
    // Hook getString
    SharedPreferencesEditor.getString = Java.use("android.content.SharedPreferences").getString;
    SharedPreferencesEditor.getString.implementation = function(key, defaultValue) {
        var result = this.getString(key, defaultValue);
        console.log("[+] SharedPreferences.getString()");
        console.log("    Key: " + key);
        console.log("    Value: " + result);
        return result;
    };
    
    // Hook EncryptedSharedPreferences (if used)
    try {
        var EncryptedSharedPreferences = Java.use("androidx.security.crypto.EncryptedSharedPreferences");
        console.log("[+] EncryptedSharedPreferences found - hooking creation");
        
        EncryptedSharedPreferences.create.overload(
            'java.lang.String',
            'java.lang.String', 
            'android.content.Context',
            'androidx.security.crypto.EncryptedSharedPreferences$PrefKeyEncryptionScheme',
            'androidx.security.crypto.EncryptedSharedPreferences$PrefValueEncryptionScheme'
        ).implementation = function(fileName, masterKeyAlias, context, keyScheme, valueScheme) {
            console.log("[+] EncryptedSharedPreferences.create() called");
            console.log("    FileName: " + fileName);
            console.log("    MasterKeyAlias: " + masterKeyAlias);
            console.log("    KeyScheme: " + keyScheme);
            console.log("    ValueScheme: " + valueScheme);
            return this.create(fileName, masterKeyAlias, context, keyScheme, valueScheme);
        };
    } catch(e) {
        console.log("[-] EncryptedSharedPreferences not found");
    }
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Vulnerability Patterns Analysis</h4>
                <CodeExample
                  language="python"
                  title="SharedPreferences Security Analysis Script"
                  code={`#!/usr/bin/env python3
"""
SharedPreferences Security Analysis Tool
"""

import xml.etree.ElementTree as ET
import re
import base64
import json
import os
from pathlib import Path

class SharedPreferencesAnalyzer:
    def __init__(self, prefs_dir):
        self.prefs_dir = Path(prefs_dir)
        self.vulnerabilities = []
        self.sensitive_patterns = [
            r'password', r'passwd', r'pwd',
            r'secret', r'key', r'token',
            r'api[_-]?key', r'auth[_-]?token',
            r'session[_-]?id', r'jwt',
            r'credit[_-]?card', r'ssn',
            r'pin', r'fingerprint'
        ]
    
    def analyze_file(self, xml_file):
        """Analyze individual SharedPreferences XML file"""
        print(f"[+] Analyzing {xml_file}")
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for child in root:
                key = child.get('name', '')
                value = child.get('value', '')
                
                # Check for sensitive keys
                for pattern in self.sensitive_patterns:
                    if re.search(pattern, key, re.IGNORECASE):
                        self.vulnerabilities.append({
                            'file': str(xml_file),
                            'type': 'Sensitive Key',
                            'key': key,
                            'value': value,
                            'pattern': pattern,
                            'severity': 'HIGH'
                        })
                
                # Check for sensitive values
                for pattern in self.sensitive_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        self.vulnerabilities.append({
                            'file': str(xml_file),
                            'type': 'Sensitive Value',
                            'key': key,
                            'value': value,
                            'pattern': pattern,
                            'severity': 'HIGH'
                        })
                
                # Check for Base64 encoded data
                if self.is_base64(value):
                    try:
                        decoded = base64.b64decode(value).decode('utf-8')
                        self.vulnerabilities.append({
                            'file': str(xml_file),
                            'type': 'Base64 Encoded Data',
                            'key': key,
                            'value': value,
                            'decoded': decoded,
                            'severity': 'MEDIUM'
                        })
                    except:
                        pass
                
                # Check for JSON data
                if value.startswith('{') and value.endswith('}'):
                    try:
                        json_data = json.loads(value)
                        self.vulnerabilities.append({
                            'file': str(xml_file),
                            'type': 'JSON Data in Preferences',
                            'key': key,
                            'json_keys': list(json_data.keys()),
                            'severity': 'MEDIUM'
                        })
                    except:
                        pass
        
        except ET.ParseError as e:
            print(f"[-] Error parsing {xml_file}: {e}")
    
    def is_base64(self, s):
        """Check if string is Base64 encoded"""
        if len(s) % 4 != 0:
            return False
        try:
            base64.b64decode(s, validate=True)
            return True
        except:
            return False
    
    def analyze_all(self):
        """Analyze all SharedPreferences files"""
        xml_files = list(self.prefs_dir.glob('*.xml'))
        
        if not xml_files:
            print("[-] No SharedPreferences XML files found")
            return
        
        for xml_file in xml_files:
            self.analyze_file(xml_file)
        
        self.generate_report()
    
    def generate_report(self):
        """Generate vulnerability report"""
        print("\\n" + "="*60)
        print("SHAREDPREFERENCES SECURITY ANALYSIS REPORT")
        print("="*60)
        
        high_count = len([v for v in self.vulnerabilities if v['severity'] == 'HIGH'])
        medium_count = len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM'])
        
        print(f"Total Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"High Severity: {high_count}")
        print(f"Medium Severity: {medium_count}")
        print()
        
        for vuln in self.vulnerabilities:
            print(f"[{vuln['severity']}] {vuln['type']}")
            print(f"  File: {vuln['file']}")
            print(f"  Key: {vuln['key']}")
            if 'value' in vuln:
                print(f"  Value: {vuln['value'][:50]}{'...' if len(vuln['value']) > 50 else ''}")
            if 'decoded' in vuln:
                print(f"  Decoded: {vuln['decoded']}")
            print()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python analyze_shared_prefs.py <shared_prefs_directory>")
        sys.exit(1)
    
    analyzer = SharedPreferencesAnalyzer(sys.argv[1])
    analyzer.analyze_all()`}
                />
              </div>
            </TabsContent>

            <TabsContent value="sqlite-analysis" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">SQLite Database Security Analysis</h3>
              <p className="text-cybr-foreground/80 mb-4">
                SQLite databases are commonly used for local data storage in Android applications. Security testing 
                involves analyzing database structure, encryption implementation, and identifying sensitive data exposure 
                through improper access controls or weak encryption.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Database Discovery and Analysis</h4>
                <CodeExample
                  language="bash"
                  title="SQLite Database Analysis"
                  code={`# Find SQLite databases
adb shell "find /data/data/com.example.app -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3'"

# Pull databases for analysis
adb pull /data/data/com.example.app/databases/ ./databases/

# Basic database analysis
for db in ./databases/*.db; do
    echo "=== Analyzing $db ==="
    file "$db"
    
    # Check if database is encrypted
    hexdump -C "$db" | head -5
    
    # If not encrypted, analyze schema
    sqlite3 "$db" ".schema"
    sqlite3 "$db" ".tables"
    
    # Dump all data
    sqlite3 "$db" ".dump" > "$db.dump"
    
    # Search for sensitive data
    grep -i "password\\|secret\\|token\\|key\\|credit" "$db.dump"
done

# Advanced analysis with sqlitebrowser
sqlitebrowser ./databases/main.db

# Check for WAL and SHM files (Write-Ahead Logging)
ls -la ./databases/*.db-wal ./databases/*.db-shm 2>/dev/null`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Runtime Database Hooking</h4>
                <CodeExample
                  language="javascript"
                  title="SQLite Runtime Analysis with Frida"
                  code={`Java.perform(function() {
    console.log("[+] SQLite Database Hooking Started");
    
    // Hook SQLiteDatabase methods
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    
    // Hook execSQL for DDL operations
    SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
        console.log("[+] SQLiteDatabase.execSQL()");
        console.log("    SQL: " + sql);
        
        // Check for sensitive table operations
        if (sql.toLowerCase().includes('password') || 
            sql.toLowerCase().includes('secret') || 
            sql.toLowerCase().includes('token')) {
            console.log("[!] SENSITIVE SQL OPERATION DETECTED");
        }
        
        return this.execSQL(sql);
    };
    
    // Hook rawQuery for SELECT operations
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, selectionArgs) {
        console.log("[+] SQLiteDatabase.rawQuery()");
        console.log("    SQL: " + sql);
        if (selectionArgs) {
            for (var i = 0; i < selectionArgs.length; i++) {
                console.log("    Arg[" + i + "]: " + selectionArgs[i]);
            }
        }
        
        var cursor = this.rawQuery(sql, selectionArgs);
        
        // Log cursor data for sensitive queries
        if (sql.toLowerCase().includes('password') || 
            sql.toLowerCase().includes('user') || 
            sql.toLowerCase().includes('auth')) {
            console.log("[!] SENSITIVE QUERY DETECTED");
            this.logCursorData(cursor);
        }
        
        return cursor;
    };
    
    // Hook SQLiteOpenHelper onCreate
    var SQLiteOpenHelper = Java.use("android.database.sqlite.SQLiteOpenHelper");
    SQLiteOpenHelper.onCreate.implementation = function(db) {
        console.log("[+] SQLiteOpenHelper.onCreate() called");
        console.log("    Database: " + db.toString());
        return this.onCreate(db);
    };
    
    // Hook Room Database (if used)
    try {
        var RoomDatabase = Java.use("androidx.room.RoomDatabase");
        RoomDatabase.getOpenHelper.implementation = function() {
            console.log("[+] Room Database detected");
            var helper = this.getOpenHelper();
            console.log("    Helper: " + helper.toString());
            return helper;
        };
    } catch(e) {
        console.log("[-] Room Database not found");
    }
    
    // Hook SQLCipher (if used)
    try {
        var SQLCipherDatabase = Java.use("net.sqlcipher.database.SQLiteDatabase");
        SQLCipherDatabase.openDatabase.overload(
            'java.lang.String', 
            'java.lang.String', 
            'net.sqlcipher.database.SQLiteDatabase$CursorFactory', 
            'int'
        ).implementation = function(path, password, factory, flags) {
            console.log("[+] SQLCipher.openDatabase() called");
            console.log("    Path: " + path);
            console.log("    Password: " + password);
            console.log("    Flags: " + flags);
            return this.openDatabase(path, password, factory, flags);
        };
    } catch(e) {
        console.log("[-] SQLCipher not found");
    }
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Database Security Assessment</h4>
                <CodeExample
                  language="python"
                  title="Comprehensive SQLite Security Analysis"
                  code={`#!/usr/bin/env python3
"""
SQLite Database Security Assessment Tool
"""

import sqlite3
import os
import re
import hashlib
from pathlib import Path

class SQLiteSecurityAnalyzer:
    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.vulnerabilities = []
        self.sensitive_patterns = [
            r'password', r'passwd', r'pwd', r'secret',
            r'token', r'key', r'auth', r'session',
            r'credit.*card', r'ssn', r'social.*security',
            r'pin', r'fingerprint', r'biometric'
        ]
    
    def check_encryption(self):
        """Check if database is encrypted"""
        with open(self.db_path, 'rb') as f:
            header = f.read(16)
        
        # SQLite header should start with "SQLite format 3"
        if header.startswith(b'SQLite format 3'):
            return False, "Database is not encrypted"
        else:
            return True, "Database appears to be encrypted or corrupted"
    
    def analyze_schema(self, conn):
        """Analyze database schema for security issues"""
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        for table in tables:
            table_name = table[0]
            
            # Check table name for sensitive patterns
            for pattern in self.sensitive_patterns:
                if re.search(pattern, table_name, re.IGNORECASE):
                    self.vulnerabilities.append({
                        'type': 'Sensitive Table Name',
                        'table': table_name,
                        'pattern': pattern,
                        'severity': 'MEDIUM'
                    })
            
            # Analyze table structure
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            
            for column in columns:
                col_name = column[1]
                col_type = column[2]
                
                # Check column names
                for pattern in self.sensitive_patterns:
                    if re.search(pattern, col_name, re.IGNORECASE):
                        self.vulnerabilities.append({
                            'type': 'Sensitive Column Name',
                            'table': table_name,
                            'column': col_name,
                            'data_type': col_type,
                            'pattern': pattern,
                            'severity': 'HIGH'
                        })
    
    def analyze_data(self, conn):
        """Analyze actual data for sensitive information"""
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        for table in tables:
            table_name = table[0]
            
            try:
                # Sample data from each table
                cursor.execute(f"SELECT * FROM {table_name} LIMIT 10")
                rows = cursor.fetchall()
                
                # Get column names
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = [col[1] for col in cursor.fetchall()]
                
                for row in rows:
                    for i, value in enumerate(row):
                        if value and isinstance(value, str):
                            # Check for sensitive data patterns
                            for pattern in self.sensitive_patterns:
                                if re.search(pattern, str(value), re.IGNORECASE):
                                    self.vulnerabilities.append({
                                        'type': 'Sensitive Data Content',
                                        'table': table_name,
                                        'column': columns[i] if i < len(columns) else f'col_{i}',
                                        'value_preview': str(value)[:50],
                                        'pattern': pattern,
                                        'severity': 'HIGH'
                                    })
                            
                            # Check for potential tokens/keys (long hex strings)
                            if re.match(r'^[a-fA-F0-9]{32,}$', str(value)):
                                self.vulnerabilities.append({
                                    'type': 'Potential Token/Key',
                                    'table': table_name,
                                    'column': columns[i] if i < len(columns) else f'col_{i}',
                                    'value_length': len(str(value)),
                                    'severity': 'MEDIUM'
                                })
            except sqlite3.Error as e:
                print(f"[-] Error analyzing table {table_name}: {e}")
    
    def check_file_permissions(self):
        """Check database file permissions"""
        stat = self.db_path.stat()
        permissions = oct(stat.st_mode)[-3:]
        
        if permissions != '600':
            self.vulnerabilities.append({
                'type': 'Insecure File Permissions',
                'file': str(self.db_path),
                'permissions': permissions,
                'recommendation': 'Should be 600 (owner read/write only)',
                'severity': 'MEDIUM'
            })
    
    def analyze(self):
        """Perform complete security analysis"""
        print(f"[+] Analyzing SQLite database: {self.db_path}")
        
        # Check if file exists
        if not self.db_path.exists():
            print(f"[-] Database file not found: {self.db_path}")
            return
        
        # Check file permissions
        self.check_file_permissions()
        
        # Check encryption
        is_encrypted, encryption_msg = self.check_encryption()
        print(f"[+] Encryption check: {encryption_msg}")
        
        if is_encrypted:
            print("[!] Database appears encrypted - limited analysis possible")
            return
        
        try:
            # Connect to database
            conn = sqlite3.connect(str(self.db_path))
            
            # Analyze schema
            self.analyze_schema(conn)
            
            # Analyze data
            self.analyze_data(conn)
            
            conn.close()
            
        except sqlite3.Error as e:
            print(f"[-] Database connection error: {e}")
            return
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate security assessment report"""
        print("\\n" + "="*60)
        print("SQLITE DATABASE SECURITY ANALYSIS REPORT")
        print("="*60)
        
        if not self.vulnerabilities:
            print("[+] No obvious security issues found")
            return
        
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"Total Issues: {len(self.vulnerabilities)}")
        for severity, count in severity_counts.items():
            print(f"{severity}: {count}")
        print()
        
        # Group by type
        by_type = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln['type']
            if vuln_type not in by_type:
                by_type[vuln_type] = []
            by_type[vuln_type].append(vuln)
        
        for vuln_type, vulns in by_type.items():
            print(f"[{vuln_type}]")
            for vuln in vulns:
                print(f"  - {vuln}")
            print()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python sqlite_analyzer.py <database_file>")
        sys.exit(1)
    
    analyzer = SQLiteSecurityAnalyzer(sys.argv[1])
    analyzer.analyze()`}
                />
              </div>
            </TabsContent>

            <TabsContent value="file-storage" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">File System Storage Analysis</h3>
              <p className="text-cybr-foreground/80 mb-4">
                Android applications can store data in various locations including internal storage, cache directories, 
                and temp files. This analysis covers file permission security, sensitive data exposure in files, 
                and improper file handling that could lead to data leakage.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Internal Storage Analysis</h4>
                <CodeExample
                  language="bash"
                  title="Complete File Storage Security Assessment"
                  code={`# Analyze application data directory
adb shell "ls -laR /data/data/com.example.app/"

# Check file permissions recursively
adb shell "find /data/data/com.example.app -exec ls -la {} \\;"

# Look for world-readable files (security issue)
adb shell "find /data/data/com.example.app -perm -004 -type f"

# Find world-writable files (major security issue)
adb shell "find /data/data/com.example.app -perm -002 -type f"

# Analyze cache directories
adb shell "ls -la /data/data/com.example.app/cache/"
adb shell "find /data/data/com.example.app/cache -type f -exec file {} \\;"

# Check temp directories
adb shell "ls -la /data/data/com.example.app/files/temp/" 2>/dev/null

# Pull all files for offline analysis
adb pull /data/data/com.example.app/ ./app_data/

# Search for sensitive content in all text files
find ./app_data -type f -exec grep -l "password\\|secret\\|token\\|key\\|auth" {} \\;

# Analyze file types
find ./app_data -type f -exec file {} \\; | sort | uniq -c | sort -nr

# Check for hidden files
find ./app_data -name ".*" -type f`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Runtime File Operations Monitoring</h4>
                <CodeExample
                  language="javascript"
                  title="File I/O Security Monitoring with Frida"
                  code={`Java.perform(function() {
    console.log("[+] File Storage Security Monitoring Started");
    
    // Hook FileOutputStream for write operations
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
        var filePath = file.getAbsolutePath();
        console.log("[+] FileOutputStream created for: " + filePath);
        
        // Check if writing to external storage
        if (filePath.includes("/sdcard/") || filePath.includes("/storage/")) {
            console.log("[!] WRITING TO EXTERNAL STORAGE: " + filePath);
        }
        
        // Check file permissions
        var permissions = file.canRead() + "," + file.canWrite() + "," + file.canExecute();
        console.log("    Permissions (R,W,X): " + permissions);
        
        return this.$init(file);
    };
    
    // Hook FileInputStream for read operations
    var FileInputStream = Java.use("java.io.FileInputStream");
    FileInputStream.$init.overload('java.io.File').implementation = function(file) {
        var filePath = file.getAbsolutePath();
        console.log("[+] FileInputStream created for: " + filePath);
        
        // Check if reading sensitive files
        var sensitivePatterns = [
            /password/i, /secret/i, /token/i, /key/i,
            /\.key$/, /\.pem$/, /\.p12$/, /\.jks$/
        ];
        
        for (var i = 0; i < sensitivePatterns.length; i++) {
            if (filePath.match(sensitivePatterns[i])) {
                console.log("[!] ACCESSING POTENTIALLY SENSITIVE FILE");
                console.log("    Pattern: " + sensitivePatterns[i]);
                break;
            }
        }
        
        return this.$init(file);
    };
    
    // Hook openFileOutput (Context method)
    var ContextImpl = Java.use("android.app.ContextImpl");
    ContextImpl.openFileOutput.implementation = function(name, mode) {
        console.log("[+] Context.openFileOutput()");
        console.log("    Filename: " + name);
        console.log("    Mode: " + mode);
        
        // Check for insecure modes
        var Context = Java.use("android.content.Context");
        if (mode & Context.MODE_WORLD_READABLE.value) {
            console.log("[!] WORLD_READABLE mode detected - SECURITY RISK!");
        }
        if (mode & Context.MODE_WORLD_WRITEABLE.value) {
            console.log("[!] WORLD_WRITEABLE mode detected - MAJOR SECURITY RISK!");
        }
        
        return this.openFileOutput(name, mode);
    };
    
    // Hook File creation methods
    var File = Java.use("java.io.File");
    File.createNewFile.implementation = function() {
        console.log("[+] File.createNewFile(): " + this.getAbsolutePath());
        
        // Check parent directory permissions
        var parent = this.getParentFile();
        if (parent) {
            console.log("    Parent dir: " + parent.getAbsolutePath());
            console.log("    Parent writable: " + parent.canWrite());
        }
        
        return this.createNewFile();
    };
    
    // Hook temporary file creation
    File.createTempFile.overload('java.lang.String', 'java.lang.String').implementation = function(prefix, suffix) {
        console.log("[+] File.createTempFile()");
        console.log("    Prefix: " + prefix);
        console.log("    Suffix: " + suffix);
        
        var tempFile = this.createTempFile(prefix, suffix);
        console.log("    Created: " + tempFile.getAbsolutePath());
        
        return tempFile;
    };
    
    // Hook RandomAccessFile
    var RandomAccessFile = Java.use("java.io.RandomAccessFile");
    RandomAccessFile.$init.overload('java.io.File', 'java.lang.String').implementation = function(file, mode) {
        console.log("[+] RandomAccessFile created");
        console.log("    File: " + file.getAbsolutePath());
        console.log("    Mode: " + mode);
        
        return this.$init(file, mode);
    };
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">File Content Security Analysis</h4>
                <CodeExample
                  language="python"
                  title="Automated File Content Security Scanner"
                  code={`#!/usr/bin/env python3
"""
Android File Storage Security Scanner
"""

import os
import re
import mimetypes
import hashlib
import json
from pathlib import Path

class FileStorageSecurityScanner:
    def __init__(self, app_data_dir):
        self.app_data_dir = Path(app_data_dir)
        self.vulnerabilities = []
        self.file_analysis = {}
        
        self.sensitive_patterns = [
            (r'password[\\s]*[=:][\\s]*[\\w]+', 'Password'),
            (r'secret[\\s]*[=:][\\s]*[\\w]+', 'Secret'),
            (r'api[_-]?key[\\s]*[=:][\\s]*[\\w]+', 'API Key'),
            (r'auth[_-]?token[\\s]*[=:][\\s]*[\\w]+', 'Auth Token'),
            (r'jwt[\\s]*[=:][\\s]*[\\w\\.-]+', 'JWT Token'),
            (r'BEGIN [A-Z]+ PRIVATE KEY', 'Private Key'),
            (r'-----BEGIN CERTIFICATE-----', 'Certificate'),
            (r'[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}', 'Credit Card'),
            (r'[0-9]{3}-[0-9]{2}-[0-9]{4}', 'SSN'),
        ]
        
        self.dangerous_permissions = [
            (0o777, 'World readable/writable/executable'),
            (0o666, 'World readable/writable'),
            (0o644, 'World readable'),
            (0o755, 'World readable/executable'),
        ]
    
    def analyze_file_permissions(self, file_path):
        """Analyze file permissions for security issues"""
        try:
            stat = file_path.stat()
            permissions = stat.st_mode & 0o777
            
            for perm, description in self.dangerous_permissions:
                if permissions & perm == perm:
                    self.vulnerabilities.append({
                        'type': 'Insecure File Permissions',
                        'file': str(file_path),
                        'permissions': oct(permissions),
                        'description': description,
                        'severity': 'HIGH' if perm & 0o006 else 'MEDIUM'
                    })
        except OSError:
            pass
    
    def analyze_file_content(self, file_path):
        """Analyze file content for sensitive information"""
        try:
            # Determine file type
            mime_type, _ = mimetypes.guess_type(str(file_path))
            
            # Only analyze text files and unknown types
            if mime_type and not mime_type.startswith('text'):
                return
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Search for sensitive patterns
            for pattern, description in self.sensitive_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    self.vulnerabilities.append({
                        'type': 'Sensitive Data in File',
                        'file': str(file_path),
                        'pattern': description,
                        'match': match.group()[:50],
                        'line_number': content[:match.start()].count('\\n') + 1,
                        'severity': 'HIGH'
                    })
            
            # Check for hardcoded URLs
            url_pattern = r'https?://[\\w\\.-]+[\\w/\\-?&=%#]*'
            urls = re.findall(url_pattern, content)
            if urls:
                self.vulnerabilities.append({
                    'type': 'Hardcoded URLs',
                    'file': str(file_path),
                    'urls': urls[:5],  # Limit to first 5 URLs
                    'severity': 'MEDIUM'
                })
            
            # Check for SQL queries (potential SQL injection points)
            sql_patterns = [
                r'SELECT\\s+.*\\s+FROM\\s+',
                r'INSERT\\s+INTO\\s+',
                r'UPDATE\\s+.*\\s+SET\\s+',
                r'DELETE\\s+FROM\\s+'
            ]
            
            for sql_pattern in sql_patterns:
                if re.search(sql_pattern, content, re.IGNORECASE):
                    self.vulnerabilities.append({
                        'type': 'SQL Query in File',
                        'file': str(file_path),
                        'severity': 'MEDIUM'
                    })
                    break
        
        except (UnicodeDecodeError, OSError):
            pass
    
    def analyze_file_types(self):
        """Analyze distribution of file types"""
        type_counts = {}
        
        for file_path in self.app_data_dir.rglob('*'):
            if file_path.is_file():
                suffix = file_path.suffix.lower()
                type_counts[suffix] = type_counts.get(suffix, 0) + 1
        
        return type_counts
    
    def find_temp_files(self):
        """Find temporary and backup files"""
        temp_patterns = [
            '*.tmp', '*.temp', '*.bak', '*.backup',
            '*.old', '*.orig', '*~', '.#*'
        ]
        
        temp_files = []
        for pattern in temp_patterns:
            temp_files.extend(self.app_data_dir.rglob(pattern))
        
        for temp_file in temp_files:
            self.vulnerabilities.append({
                'type': 'Temporary/Backup File',
                'file': str(temp_file),
                'severity': 'LOW'
            })
    
    def find_hidden_files(self):
        """Find hidden files and directories"""
        hidden_items = []
        
        for item in self.app_data_dir.rglob('.*'):
            if item.name.startswith('.') and item.name not in ['.', '..']:
                hidden_items.append(item)
        
        for hidden_item in hidden_items:
            self.vulnerabilities.append({
                'type': 'Hidden File/Directory',
                'path': str(hidden_item),
                'is_file': hidden_item.is_file(),
                'severity': 'LOW'
            })
    
    def scan(self):
        """Perform comprehensive file storage security scan"""
        print(f"[+] Scanning file storage security: {self.app_data_dir}")
        
        if not self.app_data_dir.exists():
            print(f"[-] Directory not found: {self.app_data_dir}")
            return
        
        # Analyze all files
        file_count = 0
        for file_path in self.app_data_dir.rglob('*'):
            if file_path.is_file():
                file_count += 1
                self.analyze_file_permissions(file_path)
                self.analyze_file_content(file_path)
        
        print(f"[+] Analyzed {file_count} files")
        
        # Additional analyses
        self.find_temp_files()
        self.find_hidden_files()
        
        # Generate statistics
        self.file_analysis['file_types'] = self.analyze_file_types()
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive security report"""
        print("\\n" + "="*60)
        print("FILE STORAGE SECURITY ANALYSIS REPORT")
        print("="*60)
        
        if not self.vulnerabilities:
            print("[+] No security issues found")
            return
        
        # Summary statistics
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"Total Issues: {len(self.vulnerabilities)}")
        for severity, count in severity_counts.items():
            print(f"{severity}: {count}")
        print()
        
        # File type distribution
        print("File Type Distribution:")
        for file_type, count in sorted(self.file_analysis['file_types'].items(), 
                                     key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {file_type or 'no extension'}: {count}")
        print()
        
        # Detailed vulnerabilities
        for vuln in sorted(self.vulnerabilities, key=lambda x: x['severity'], reverse=True):
            print(f"[{vuln['severity']}] {vuln['type']}")
            for key, value in vuln.items():
                if key not in ['type', 'severity']:
                    print(f"  {key}: {value}")
            print()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python file_storage_scanner.py <app_data_directory>")
        sys.exit(1)
    
    scanner = FileStorageSecurityScanner(sys.argv[1])
    scanner.scan()`}
                />
              </div>
            </TabsContent>

            <TabsContent value="keystore-analysis" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Android Keystore Security Analysis</h3>
              <p className="text-cybr-foreground/80 mb-4">
                The Android Keystore system provides hardware-backed cryptographic key storage and operations. 
                This analysis covers keystore implementation review, key management security, and identifying 
                vulnerabilities in cryptographic key handling and storage mechanisms.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Keystore Implementation Analysis</h4>
                <CodeExample
                  language="javascript"
                  title="Android Keystore Runtime Analysis"
                  code={`Java.perform(function() {
    console.log("[+] Android Keystore Analysis Started");
    
    // Hook KeyStore operations
    var KeyStore = Java.use("java.security.KeyStore");
    
    // Hook KeyStore.load()
    KeyStore.load.overload('java.io.InputStream', '[C').implementation = function(stream, password) {
        console.log("[+] KeyStore.load() called");
        if (password) {
            console.log("    Password length: " + password.length);
            // Don't log actual password for security
        }
        return this.load(stream, password);
    };
    
    // Hook KeyStore.getKey()
    KeyStore.getKey.implementation = function(alias, password) {
        console.log("[+] KeyStore.getKey() called");
        console.log("    Alias: " + alias);
        if (password) {
            console.log("    Password provided: true");
        }
        
        var key = this.getKey(alias, password);
        if (key) {
            console.log("    Key algorithm: " + key.getAlgorithm());
            console.log("    Key format: " + key.getFormat());
        }
        return key;
    };
    
    // Hook KeyStore.setKeyEntry()
    KeyStore.setKeyEntry.overload('java.lang.String', 'java.security.Key', '[C', '[Ljava.security.cert.Certificate;')
        .implementation = function(alias, key, password, certChain) {
        console.log("[+] KeyStore.setKeyEntry() called");
        console.log("    Alias: " + alias);
        console.log("    Key algorithm: " + key.getAlgorithm());
        if (password) {
            console.log("    Password protected: true");
        }
        return this.setKeyEntry(alias, key, password, certChain);
    };
    
    // Hook KeyGenerator for Android Keystore
    var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
    KeyGenerator.getInstance.overload('java.lang.String').implementation = function(algorithm) {
        console.log("[+] KeyGenerator.getInstance() called");
        console.log("    Algorithm: " + algorithm);
        return this.getInstance(algorithm);
    };
    
    // Hook KeyGenParameterSpec (Android M+)
    try {
        var KeyGenParameterSpec = Java.use("android.security.keystore.KeyGenParameterSpec");
        var KeyGenParameterSpecBuilder = Java.use("android.security.keystore.KeyGenParameterSpec$Builder");
        
        KeyGenParameterSpecBuilder.build.implementation = function() {
            console.log("[+] KeyGenParameterSpec.Builder.build() called");
            
            var spec = this.build();
            
            // Log key specifications
            console.log("    Key alias: " + spec.getKeystoreAlias());
            console.log("    Key size: " + spec.getKeySize());
            console.log("    Purposes: " + spec.getPurposes());
            console.log("    User auth required: " + spec.isUserAuthenticationRequired());
            console.log("    User presence required: " + spec.isUserPresenceRequired());
            
            // Check for security issues
            if (!spec.isUserAuthenticationRequired()) {
                console.log("[!] KEY WITHOUT USER AUTHENTICATION - POTENTIAL SECURITY RISK");
            }
            
            return spec;
        };
    } catch(e) {
        console.log("[-] KeyGenParameterSpec not available (API < 23)");
    }
    
    // Hook KeyProtection (Android M+)
    try {
        var KeyProtection = Java.use("android.security.keystore.KeyProtection");
        var KeyProtectionBuilder = Java.use("android.security.keystore.KeyProtection$Builder");
        
        KeyProtectionBuilder.build.implementation = function() {
            console.log("[+] KeyProtection.Builder.build() called");
            
            var protection = this.build();
            console.log("    User auth required: " + protection.isUserAuthenticationRequired());
            console.log("    User presence required: " + protection.isUserPresenceRequired());
            
            return protection;
        };
    } catch(e) {
        console.log("[-] KeyProtection not available");
    }
    
    // Hook BiometricPrompt (if available)
    try {
        var BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
        BiometricPrompt.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo')
            .implementation = function(promptInfo) {
            console.log("[+] BiometricPrompt.authenticate() called");
            console.log("    Title: " + promptInfo.getTitle());
            console.log("    Subtitle: " + promptInfo.getSubtitle());
            
            return this.authenticate(promptInfo);
        };
    } catch(e) {
        console.log("[-] BiometricPrompt not found");
    }
    
    // Hook FingerprintManager (deprecated but still used)
    try {
        var FingerprintManager = Java.use("android.hardware.fingerprint.FingerprintManager");
        FingerprintManager.authenticate.overload(
            'android.hardware.fingerprint.FingerprintManager$CryptoObject',
            'android.os.CancellationSignal',
            'int',
            'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback',
            'android.os.Handler'
        ).implementation = function(crypto, cancel, flags, callback, handler) {
            console.log("[+] FingerprintManager.authenticate() called");
            if (crypto) {
                console.log("    CryptoObject provided: true");
                var cipher = crypto.getCipher();
                if (cipher) {
                    console.log("    Cipher algorithm: " + cipher.getAlgorithm());
                }
            }
            return this.authenticate(crypto, cancel, flags, callback, handler);
        };
    } catch(e) {
        console.log("[-] FingerprintManager not found");
    }
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Keystore Security Assessment</h4>
                <CodeExample
                  language="bash"
                  title="Keystore Security Analysis Commands"
                  code={`# Check for keystore files in application directory
adb shell "find /data/data/com.example.app -name '*.jks' -o -name '*.p12' -o -name '*.pfx' -o -name '*.keystore'"

# Look for hardcoded keystore passwords
grep -r "keystore\\|truststore" ./decompiled_app/
grep -r "password.*=.*[\"'][^\"']*[\"']" ./decompiled_app/

# Check for default keystore passwords
grep -r "changeit\\|password\\|123456\\|android" ./decompiled_app/

# Analyze certificate usage
grep -r "X509Certificate\\|TrustManager\\|SSLContext" ./decompiled_app/

# Check for insecure random number generation
grep -r "Random\\|SecureRandom" ./decompiled_app/

# Look for hardcoded certificates
grep -r "BEGIN CERTIFICATE\\|BEGIN PRIVATE KEY" ./decompiled_app/

# Check for keystore configuration files
find ./decompiled_app -name "*.properties" -o -name "*.xml" | xargs grep -l "keystore\\|truststore"

# Android Keystore specific checks
grep -r "AndroidKeyStore" ./decompiled_app/
grep -r "KeyGenParameterSpec" ./decompiled_app/
grep -r "setUserAuthenticationRequired" ./decompiled_app/

# Check for biometric authentication
grep -r "BiometricPrompt\\|FingerprintManager" ./decompiled_app/
grep -r "USE_FINGERPRINT\\|USE_BIOMETRIC" ./decompiled_app/`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Cryptographic Key Analysis</h4>
                <CodeExample
                  language="python"
                  title="Keystore Security Assessment Tool"
                  code={`#!/usr/bin/env python3
"""
Android Keystore Security Assessment Tool
"""

import re
import os
import subprocess
from pathlib import Path

class KeystoreSecurityAnalyzer:
    def __init__(self, app_dir):
        self.app_dir = Path(app_dir)
        self.vulnerabilities = []
        
    def find_keystore_files(self):
        """Find keystore files in application directory"""
        keystore_patterns = ['*.jks', '*.p12', '*.pfx', '*.keystore', '*.bks']
        keystore_files = []
        
        for pattern in keystore_patterns:
            keystore_files.extend(self.app_dir.rglob(pattern))
        
        return keystore_files
    
    def analyze_source_code(self):
        """Analyze source code for keystore-related vulnerabilities"""
        java_files = list(self.app_dir.rglob('*.java')) + list(self.app_dir.rglob('*.kt'))
        
        for file_path in java_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Check for hardcoded keystore passwords
                password_patterns = [
                    r'keystore.*password.*=.*["\']([^"\']+)["\']',
                    r'truststore.*password.*=.*["\']([^"\']+)["\']',
                    r'\.load\\([^)]*,\\s*["\']([^"\']+)["\']\\s*\\.toCharArray\\(\\)',
                ]
                
                for pattern in password_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        password = match.group(1) if match.groups() else "found"
                        self.vulnerabilities.append({
                            'type': 'Hardcoded Keystore Password',
                            'file': str(file_path),
                            'password': password,
                            'line': content[:match.start()].count('\\n') + 1,
                            'severity': 'HIGH'
                        })
                
                # Check for default passwords
                default_passwords = ['changeit', 'password', '123456', 'android', 'default']
                for default_pwd in default_passwords:
                    if default_pwd in content.lower():
                        self.vulnerabilities.append({
                            'type': 'Default Keystore Password',
                            'file': str(file_path),
                            'password': default_pwd,
                            'severity': 'HIGH'
                        })
                
                # Check for insecure TrustManager implementations
                if 'TrustManager' in content:
                    # Look for custom TrustManager that accepts all certificates
                    if re.search(r'checkServerTrusted\\s*\\([^)]*\\)\\s*{\\s*}', content):
                        self.vulnerabilities.append({
                            'type': 'Insecure TrustManager - Accepts All Certificates',
                            'file': str(file_path),
                            'severity': 'CRITICAL'
                        })
                
                # Check for insecure HostnameVerifier
                if 'HostnameVerifier' in content:
                    if re.search(r'verify\\s*\\([^)]*\\)\\s*{\\s*return\\s+true\\s*;\\s*}', content):
                        self.vulnerabilities.append({
                            'type': 'Insecure HostnameVerifier - Always Returns True',
                            'file': str(file_path),
                            'severity': 'CRITICAL'
                        })
                
                # Check for weak key generation
                weak_patterns = [
                    r'KeyGenerator\\.getInstance\\s*\\(\\s*["\']DES["\']',
                    r'KeyGenerator\\.getInstance\\s*\\(\\s*["\']RC4["\']',
                    r'Cipher\\.getInstance\\s*\\(\\s*["\']DES/',
                ]
                
                for pattern in weak_patterns:
                    if re.search(pattern, content):
                        self.vulnerabilities.append({
                            'type': 'Weak Cryptographic Algorithm',
                            'file': str(file_path),
                            'pattern': pattern,
                            'severity': 'HIGH'
                        })
                
                # Check Android Keystore usage
                if 'AndroidKeyStore' in content:
                    # Check if user authentication is required
                    if 'setUserAuthenticationRequired' not in content:
                        self.vulnerabilities.append({
                            'type': 'Android Keystore Without User Authentication',
                            'file': str(file_path),
                            'severity': 'MEDIUM'
                        })
                
            except Exception as e:
                print(f"[-] Error analyzing {file_path}: {e}")
    
    def analyze_keystore_files(self, keystore_files):
        """Analyze actual keystore files"""
        for keystore_file in keystore_files:
            try:
                # Try to analyze with keytool
                cmd = f"keytool -list -keystore {keystore_file} -storepass changeit"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.vulnerabilities.append({
                        'type': 'Keystore with Default Password',
                        'file': str(keystore_file),
                        'password': 'changeit',
                        'severity': 'CRITICAL'
                    })
                
                # Check file permissions
                stat = keystore_file.stat()
                permissions = oct(stat.st_mode)[-3:]
                
                if permissions != '600':
                    self.vulnerabilities.append({
                        'type': 'Insecure Keystore File Permissions',
                        'file': str(keystore_file),
                        'permissions': permissions,
                        'severity': 'HIGH'
                    })
                
            except Exception as e:
                print(f"[-] Error analyzing keystore {keystore_file}: {e}")
    
    def check_configuration_files(self):
        """Check configuration files for keystore settings"""
        config_files = []
        config_files.extend(self.app_dir.rglob('*.properties'))
        config_files.extend(self.app_dir.rglob('*.xml'))
        config_files.extend(self.app_dir.rglob('*.json'))
        
        for config_file in config_files:
            try:
                with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Look for keystore configurations
                keystore_configs = [
                    r'keystore[._-]?path',
                    r'keystore[._-]?password',
                    r'truststore[._-]?path',
                    r'truststore[._-]?password',
                    r'ssl[._-]?keystore',
                    r'javax\\.net\\.ssl\\.keyStore'
                ]
                
                for config_pattern in keystore_configs:
                    if re.search(config_pattern, content, re.IGNORECASE):
                        self.vulnerabilities.append({
                            'type': 'Keystore Configuration in File',
                            'file': str(config_file),
                            'pattern': config_pattern,
                            'severity': 'MEDIUM'
                        })
                        break
                
            except Exception as e:
                print(f"[-] Error analyzing config file {config_file}: {e}")
    
    def analyze(self):
        """Perform comprehensive keystore security analysis"""
        print(f"[+] Starting keystore security analysis: {self.app_dir}")
        
        # Find keystore files
        keystore_files = self.find_keystore_files()
        if keystore_files:
            print(f"[+] Found {len(keystore_files)} keystore files")
            self.analyze_keystore_files(keystore_files)
        else:
            print("[+] No keystore files found")
        
        # Analyze source code
        self.analyze_source_code()
        
        # Check configuration files
        self.check_configuration_files()
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate keystore security assessment report"""
        print("\\n" + "="*60)
        print("KEYSTORE SECURITY ANALYSIS REPORT")
        print("="*60)
        
        if not self.vulnerabilities:
            print("[+] No keystore security issues found")
            return
        
        # Count by severity
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"Total Issues: {len(self.vulnerabilities)}")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_counts:
                print(f"{severity}: {severity_counts[severity]}")
        print()
        
        # Detailed findings
        for vuln in sorted(self.vulnerabilities, 
                          key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}[x['severity']], 
                          reverse=True):
            print(f"[{vuln['severity']}] {vuln['type']}")
            for key, value in vuln.items():
                if key not in ['type', 'severity']:
                    print(f"  {key}: {value}")
            print()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python keystore_analyzer.py <app_directory>")
        sys.exit(1)
    
    analyzer = KeystoreSecurityAnalyzer(sys.argv[1])
    analyzer.analyze()`}
                />
              </div>
            </TabsContent>

            <TabsContent value="external-storage" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">External Storage Security Analysis</h3>
              <p className="text-cybr-foreground/80 mb-4">
                External storage on Android is world-accessible and presents significant security risks when used 
                improperly. This analysis covers external storage misuse, SD card security, scoped storage compliance, 
                and data exposure through publicly accessible storage locations.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">External Storage Discovery</h4>
                <CodeExample
                  language="bash"
                  title="External Storage Security Assessment"
                  code={`# Find application data on external storage
adb shell "find /sdcard -name '*com.example.app*' -type d"
adb shell "find /storage/emulated -name '*com.example.app*' -type d"

# Check for sensitive files on external storage
adb shell "find /sdcard -name '*.db' -o -name '*.sqlite' -o -name '*.xml' -o -name '*.json'"

# Look for application-specific directories
adb shell "ls -la /sdcard/Android/data/com.example.app/"
adb shell "ls -la /sdcard/Android/obb/com.example.app/"

# Check for cache files on external storage
adb shell "find /sdcard -name '*cache*' -type d"
adb shell "find /sdcard -name '*.tmp' -o -name '*.temp'"

# Pull external storage data for analysis
adb pull /sdcard/Android/data/com.example.app/ ./external_data/

# Analyze downloaded files
find ./external_data -type f -exec file {} \\;
find ./external_data -name "*.db" -exec sqlite3 {} ".schema" \\;

# Search for sensitive content
grep -r "password\\|secret\\|token\\|key" ./external_data/
grep -r "api_key\\|auth\\|session" ./external_data/

# Check for backup files
find ./external_data -name "*.bak" -o -name "*.backup" -o -name "*~"

# Look for image metadata (EXIF data)
find ./external_data -name "*.jpg" -o -name "*.jpeg" | head -5 | xargs exiftool`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Runtime External Storage Monitoring</h4>
                <CodeExample
                  language="javascript"
                  title="External Storage Access Monitoring"
                  code={`Java.perform(function() {
    console.log("[+] External Storage Security Monitoring Started");
    
    // Hook Environment.getExternalStorageDirectory()
    var Environment = Java.use("android.os.Environment");
    Environment.getExternalStorageDirectory.implementation = function() {
        var result = this.getExternalStorageDirectory();
        console.log("[+] Environment.getExternalStorageDirectory() called");
        console.log("    Path: " + result.getAbsolutePath());
        console.log("[!] EXTERNAL STORAGE ACCESS - POTENTIAL SECURITY RISK");
        return result;
    };
    
    // Hook getExternalFilesDir()
    var ContextImpl = Java.use("android.app.ContextImpl");
    ContextImpl.getExternalFilesDir.implementation = function(type) {
        var result = this.getExternalFilesDir(type);
        console.log("[+] Context.getExternalFilesDir() called");
        if (result) {
            console.log("    Path: " + result.getAbsolutePath());
        }
        console.log("    Type: " + type);
        return result;
    };
    
    // Hook getExternalCacheDir()
    ContextImpl.getExternalCacheDir.implementation = function() {
        var result = this.getExternalCacheDir();
        console.log("[+] Context.getExternalCacheDir() called");
        if (result) {
            console.log("    Path: " + result.getAbsolutePath());
            console.log("[!] EXTERNAL CACHE USAGE - DATA MAY BE ACCESSIBLE");
        }
        return result;
    };
    
    // Hook MediaStore operations
    try {
        var MediaStore = Java.use("android.provider.MediaStore");
        var ContentResolver = Java.use("android.content.ContentResolver");
        
        // This is complex due to MediaStore being primarily constants
        // Hook ContentResolver query instead
        ContentResolver.query.overload(
            'android.net.Uri',
            '[Ljava.lang.String;',
            'java.lang.String',
            '[Ljava.lang.String;',
            'java.lang.String'
        ).implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
            console.log("[+] ContentResolver.query() called");
            console.log("    URI: " + uri.toString());
            
            // Check if accessing MediaStore
            if (uri.toString().includes("media")) {
                console.log("[!] MEDIASTORE ACCESS DETECTED");
                console.log("    Selection: " + selection);
            }
            
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
        
    } catch(e) {
        console.log("[-] MediaStore hooking failed: " + e);
    }
    
    // Hook File operations on external paths
    var File = Java.use("java.io.File");
    var originalInit = File.$init.overload('java.lang.String');
    originalInit.implementation = function(pathname) {
        console.log("[+] File created: " + pathname);
        
        // Check if path is external storage
        if (pathname.includes("/sdcard/") || 
            pathname.includes("/storage/emulated/") ||
            pathname.includes("/mnt/")) {
            console.log("[!] EXTERNAL STORAGE FILE ACCESS");
            console.log("    Path: " + pathname);
            
            // Log call stack for context
            console.log("    Call stack:");
            Java.perform(function() {
                var Exception = Java.use("java.lang.Exception");
                var ex = Exception.$new();
                var stack = ex.getStackTrace();
                for (var i = 0; i < Math.min(stack.length, 5); i++) {
                    console.log("      " + stack[i].toString());
                }
            });
        }
        
        return originalInit.call(this, pathname);
    };
    
    // Hook Storage Access Framework (SAF)
    try {
        var Intent = Java.use("android.content.Intent");
        var Activity = Java.use("android.app.Activity");
        
        Activity.startActivityForResult.overload('android.content.Intent', 'int').implementation = function(intent, requestCode) {
            console.log("[+] Activity.startActivityForResult() called");
            
            var action = intent.getAction();
            if (action && (action.includes("OPEN_DOCUMENT") || 
                          action.includes("CREATE_DOCUMENT") || 
                          action.includes("OPEN_DOCUMENT_TREE"))) {
                console.log("[+] Storage Access Framework usage detected");
                console.log("    Action: " + action);
                console.log("    Request Code: " + requestCode);
            }
            
            return this.startActivityForResult(intent, requestCode);
        };
        
    } catch(e) {
        console.log("[-] SAF hooking failed: " + e);
    }
    
    // Hook scoped storage checks (Android 10+)
    try {
        var Build = Java.use("android.os.Build");
        var VERSION = Java.use("android.os.Build$VERSION");
        
        if (VERSION.SDK_INT.value >= 29) {
            console.log("[+] Scoped Storage era (API 29+) - Monitoring compliance");
            
            // Monitor requestLegacyExternalStorage usage
            // This would typically be in AndroidManifest.xml
        }
        
    } catch(e) {
        console.log("[-] Scoped storage monitoring failed: " + e);
    }
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">External Storage Security Scanner</h4>
                <CodeExample
                  language="python"
                  title="External Storage Security Analysis Tool"
                  code={`#!/usr/bin/env python3
"""
External Storage Security Scanner for Android Apps
"""

import os
import re
import json
import sqlite3
from pathlib import Path
from PIL import Image
from PIL.ExifTags import TAGS

class ExternalStorageSecurityScanner:
    def __init__(self, external_data_dir, package_name):
        self.external_data_dir = Path(external_data_dir)
        self.package_name = package_name
        self.vulnerabilities = []
        self.file_analysis = {}
        
    def analyze_file_locations(self):
        """Analyze file locations for security risks"""
        # Check for files in root of external storage
        root_files = []
        try:
            # This would be from pulled /sdcard data
            sdcard_root = self.external_data_dir.parent / "sdcard_root"
            if sdcard_root.exists():
                for item in sdcard_root.iterdir():
                    if self.package_name.lower() in item.name.lower():
                        root_files.append(item)
        except:
            pass
        
        if root_files:
            self.vulnerabilities.append({
                'type': 'App Data in External Storage Root',
                'files': [str(f) for f in root_files],
                'severity': 'HIGH',
                'description': 'Application data found in external storage root - world accessible'
            })
    
    def analyze_database_files(self):
        """Analyze SQLite databases on external storage"""
        db_files = list(self.external_data_dir.rglob('*.db'))
        db_files.extend(list(self.external_data_dir.rglob('*.sqlite')))
        db_files.extend(list(self.external_data_dir.rglob('*.sqlite3')))
        
        for db_file in db_files:
            self.vulnerabilities.append({
                'type': 'Database on External Storage',
                'file': str(db_file),
                'severity': 'CRITICAL',
                'description': 'SQLite database stored on external storage - world accessible'
            })
            
            # Analyze database content
            try:
                conn = sqlite3.connect(str(db_file))
                cursor = conn.cursor()
                
                # Get table names
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                
                sensitive_tables = []
                for table in tables:
                    table_name = table[0]
                    if any(keyword in table_name.lower() for keyword in 
                          ['user', 'password', 'auth', 'session', 'token', 'key']):
                        sensitive_tables.append(table_name)
                
                if sensitive_tables:
                    self.vulnerabilities.append({
                        'type': 'Sensitive Database Tables on External Storage',
                        'file': str(db_file),
                        'tables': sensitive_tables,
                        'severity': 'CRITICAL'
                    })
                
                conn.close()
                
            except sqlite3.Error as e:
                print(f"[-] Error analyzing database {db_file}: {e}")
    
    def analyze_configuration_files(self):
        """Analyze configuration files on external storage"""
        config_files = []
        config_files.extend(list(self.external_data_dir.rglob('*.xml')))
        config_files.extend(list(self.external_data_dir.rglob('*.json')))
        config_files.extend(list(self.external_data_dir.rglob('*.properties')))
        config_files.extend(list(self.external_data_dir.rglob('*.conf')))
        config_files.extend(list(self.external_data_dir.rglob('*.cfg')))
        
        for config_file in config_files:
            self.vulnerabilities.append({
                'type': 'Configuration File on External Storage',
                'file': str(config_file),
                'severity': 'HIGH',
                'description': 'Configuration file on external storage may contain sensitive data'
            })
            
            # Analyze content for sensitive data
            try:
                with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                sensitive_patterns = [
                    (r'password[\\s]*[=:][\\s]*[\\w]+', 'Password'),
                    (r'secret[\\s]*[=:][\\s]*[\\w]+', 'Secret'),
                    (r'api[_-]?key[\\s]*[=:][\\s]*[\\w]+', 'API Key'),
                    (r'token[\\s]*[=:][\\s]*[\\w]+', 'Token'),
                ]
                
                for pattern, desc in sensitive_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.vulnerabilities.append({
                            'type': f'Sensitive Data in External Configuration: {desc}',
                            'file': str(config_file),
                            'severity': 'CRITICAL'
                        })
            except:
                pass
    
    def analyze_image_metadata(self):
        """Analyze image files for EXIF data"""
        image_files = []
        image_files.extend(list(self.external_data_dir.rglob('*.jpg')))
        image_files.extend(list(self.external_data_dir.rglob('*.jpeg')))
        image_files.extend(list(self.external_data_dir.rglob('*.png')))
        image_files.extend(list(self.external_data_dir.rglob('*.tiff')))
        
        images_with_exif = []
        
        for image_file in image_files[:10]:  # Limit to first 10 images
            try:
                image = Image.open(image_file)
                exifdata = image.getexif()
                
                if exifdata:
                    exif_dict = {}
                    for tag_id in exifdata:
                        tag = TAGS.get(tag_id, tag_id)
                        data = exifdata.get(tag_id)
                        exif_dict[tag] = data
                    
                    # Check for location data
                    location_tags = ['GPSInfo', 'GPS', 'DateTime', 'DateTimeOriginal']
                    has_sensitive_exif = any(tag in exif_dict for tag in location_tags)
                    
                    if has_sensitive_exif:
                        images_with_exif.append({
                            'file': str(image_file),
                            'exif_tags': list(exif_dict.keys())
                        })
            except Exception as e:
                continue
        
        if images_with_exif:
            self.vulnerabilities.append({
                'type': 'Images with EXIF Data on External Storage',
                'images': images_with_exif,
                'severity': 'LOW',
                'description': 'Images contain metadata that may reveal sensitive information'
            })
    
    def analyze_backup_files(self):
        """Analyze backup and temporary files"""
        backup_patterns = ['*.bak', '*.backup', '*.old', '*.orig', '*~', '*.tmp', '*.temp']
        backup_files = []
        
        for pattern in backup_patterns:
            backup_files.extend(list(self.external_data_dir.rglob(pattern)))
        
        if backup_files:
            self.vulnerabilities.append({
                'type': 'Backup/Temporary Files on External Storage',
                'files': [str(f) for f in backup_files],
                'severity': 'MEDIUM',
                'description': 'Backup files may contain sensitive data from previous versions'
            })
    
    def check_scoped_storage_compliance(self):
        """Check for scoped storage compliance issues"""
        # This would require analyzing the app's manifest and code
        # For now, we'll check for files outside the app-specific directory
        
        app_specific_path = f"Android/data/{self.package_name}"
        files_outside_scope = []
        
        for file_path in self.external_data_dir.rglob('*'):
            if file_path.is_file():
                path_str = str(file_path)
                if app_specific_path not in path_str:
                    files_outside_scope.append(str(file_path))
        
        if files_outside_scope:
            self.vulnerabilities.append({
                'type': 'Files Outside App-Specific Directory',
                'files': files_outside_scope[:10],  # Limit output
                'severity': 'MEDIUM',
                'description': 'Files found outside app-specific external storage directory'
            })
    
    def scan(self):
        """Perform comprehensive external storage security scan"""
        print(f"[+] Starting external storage security scan: {self.external_data_dir}")
        
        if not self.external_data_dir.exists():
            print(f"[-] Directory not found: {self.external_data_dir}")
            return
        
        # Perform all analyses
        self.analyze_file_locations()
        self.analyze_database_files()
        self.analyze_configuration_files()
        self.analyze_image_metadata()
        self.analyze_backup_files()
        self.check_scoped_storage_compliance()
        
        # Generate statistics
        file_count = sum(1 for _ in self.external_data_dir.rglob('*') if _.is_file())
        self.file_analysis['total_files'] = file_count
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate external storage security report"""
        print("\\n" + "="*60)
        print("EXTERNAL STORAGE SECURITY ANALYSIS REPORT")
        print("="*60)
        print(f"Package: {self.package_name}")
        print(f"Total Files Analyzed: {self.file_analysis.get('total_files', 0)}")
        print()
        
        if not self.vulnerabilities:
            print("[+] No external storage security issues found")
            return
        
        # Count by severity
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"Total Issues: {len(self.vulnerabilities)}")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_counts:
                print(f"{severity}: {severity_counts[severity]}")
        print()
        
        # Detailed findings
        for vuln in sorted(self.vulnerabilities, 
                          key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}[x['severity']], 
                          reverse=True):
            print(f"[{vuln['severity']}] {vuln['type']}")
            for key, value in vuln.items():
                if key not in ['type', 'severity']:
                    if isinstance(value, list) and len(value) > 5:
                        print(f"  {key}: {value[:5]} ... (and {len(value)-5} more)")
                    else:
                        print(f"  {key}: {value}")
            print()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python external_storage_scanner.py <external_data_dir> <package_name>")
        sys.exit(1)
    
    scanner = ExternalStorageSecurityScanner(sys.argv[1], sys.argv[2])
    scanner.scan()`}
                />
              </div>
            </TabsContent>

            <TabsContent value="backup-analysis" className="space-y-4">
              <h3 className="text-xl font-semibold text-cybr-primary">Application Backup Analysis</h3>
              <p className="text-cybr-foreground/80 mb-4">
                Android's backup mechanisms can expose sensitive application data if not properly configured. 
                This analysis covers Auto Backup, allowBackup settings, Key/Value Backup, and data exposure 
                through various backup channels including ADB backup and cloud backup services.
              </p>

              <div className="space-y-4">
                <h4 className="text-lg font-medium text-cybr-secondary">Backup Configuration Analysis</h4>
                <CodeExample
                  language="bash"
                  title="Backup Security Assessment"
                  code={`# Check allowBackup setting in AndroidManifest.xml
grep -n "android:allowBackup" AndroidManifest.xml

# Check for backup rules configuration
grep -n "android:backupAgent" AndroidManifest.xml
grep -n "android:fullBackupContent" AndroidManifest.xml
grep -n "android:dataExtractionRules" AndroidManifest.xml

# Test ADB backup (if allowBackup=true)
adb backup -all -apk -shared -nosystem com.example.app
# This creates backup.ab file

# Extract ADB backup
dd if=backup.ab bs=1 skip=24 | python -c "import zlib,sys;sys.stdout.write(zlib.decompress(sys.stdin.read()))" | tar -xvf -

# Check for backup rules files
find ./decompiled_app -name "*backup*" -type f
find ./decompiled_app -name "xml" | grep -i backup

# Analyze backup rules (if present)
cat ./decompiled_app/res/xml/backup_rules.xml
cat ./decompiled_app/res/xml/data_extraction_rules.xml

# Check for cloud backup configuration
grep -r "BackupAgent\\|BackupAgentHelper" ./decompiled_app/
grep -r "onBackup\\|onRestore" ./decompiled_app/

# Test backup with specific package
adb backup -apk -shared com.example.app

# List backup contents
tar -tf extracted_backup.tar | head -20

# Check for sensitive data in backup
tar -xf extracted_backup.tar
find ./apps/com.example.app -name "*.db" -o -name "*.xml" -o -name "*.json"
grep -r "password\\|secret\\|token" ./apps/com.example.app/`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Runtime Backup Monitoring</h4>
                <CodeExample
                  language="javascript"
                  title="Backup Agent Security Monitoring"
                  code={`Java.perform(function() {
    console.log("[+] Backup Security Monitoring Started");
    
    // Hook BackupAgent methods
    try {
        var BackupAgent = Java.use("android.app.backup.BackupAgent");
        
        BackupAgent.onBackup.implementation = function(oldState, data, newState) {
            console.log("[+] BackupAgent.onBackup() called");
            console.log("    Old state size: " + (oldState ? oldState.available() : 0));
            console.log("    Data stream available: " + (data ? "yes" : "no"));
            console.log("[!] BACKUP OPERATION DETECTED");
            
            // Log what's being backed up (be careful not to log sensitive data)
            if (data) {
                console.log("    Backup data stream created");
            }
            
            return this.onBackup(oldState, data, newState);
        };
        
        BackupAgent.onRestore.implementation = function(data, appVersionCode, newState) {
            console.log("[+] BackupAgent.onRestore() called");
            console.log("    App version: " + appVersionCode);
            console.log("    Data available: " + (data ? data.available() : 0) + " bytes");
            console.log("[!] RESTORE OPERATION DETECTED");
            
            return this.onRestore(data, appVersionCode, newState);
        };
        
    } catch(e) {
        console.log("[-] BackupAgent not found or not used");
    }
    
    // Hook BackupAgentHelper
    try {
        var BackupAgentHelper = Java.use("android.app.backup.BackupAgentHelper");
        
        BackupAgentHelper.addHelper.implementation = function(keyPrefix, helper) {
            console.log("[+] BackupAgentHelper.addHelper() called");
            console.log("    Key prefix: " + keyPrefix);
            console.log("    Helper: " + helper.getClass().getName());
            
            return this.addHelper(keyPrefix, helper);
        };
        
    } catch(e) {
        console.log("[-] BackupAgentHelper not found");
    }
    
    // Hook SharedPreferencesBackupHelper
    try {
        var SharedPreferencesBackupHelper = Java.use("android.app.backup.SharedPreferencesBackupHelper");
        
        SharedPreferencesBackupHelper.$init.overload('[Ljava.lang.String;').implementation = function(prefGroups) {
            console.log("[+] SharedPreferencesBackupHelper created");
            console.log("    Preference groups: " + prefGroups);
            console.log("[!] SHARED PREFERENCES BACKUP ENABLED");
            
            for (var i = 0; i < prefGroups.length; i++) {
                console.log("      Group[" + i + "]: " + prefGroups[i]);
            }
            
            return this.$init(prefGroups);
        };
        
    } catch(e) {
        console.log("[-] SharedPreferencesBackupHelper not found");
    }
    
    // Hook FileBackupHelper
    try {
        var FileBackupHelper = Java.use("android.app.backup.FileBackupHelper");
        
        FileBackupHelper.$init.overload('android.content.Context', '[Ljava.lang.String;').implementation = function(context, files) {
            console.log("[+] FileBackupHelper created");
            console.log("    Files to backup: " + files.length);
            console.log("[!] FILE BACKUP ENABLED");
            
            for (var i = 0; i < files.length; i++) {
                console.log("      File[" + i + "]: " + files[i]);
                
                // Check for sensitive file patterns
                var filename = files[i];
                if (filename.includes("password") || 
                    filename.includes("secret") || 
                    filename.includes("key") ||
                    filename.includes("token")) {
                    console.log("[!] SENSITIVE FILE IN BACKUP: " + filename);
                }
            }
            
            return this.$init(context, files);
        };
        
    } catch(e) {
        console.log("[-] FileBackupHelper not found");
    }
    
    // Hook BackupManager
    try {
        var BackupManager = Java.use("android.app.backup.BackupManager");
        
        BackupManager.dataChanged.overload().implementation = function() {
            console.log("[+] BackupManager.dataChanged() called");
            console.log("[!] BACKUP DATA CHANGE NOTIFICATION");
            
            return this.dataChanged();
        };
        
        BackupManager.requestRestore.implementation = function(observer) {
            console.log("[+] BackupManager.requestRestore() called");
            console.log("[!] RESTORE OPERATION REQUESTED");
            
            return this.requestRestore(observer);
        };
        
    } catch(e) {
        console.log("[-] BackupManager not accessible");
    }
    
    // Hook Auto Backup exclusions
    try {
        // Monitor file operations that might be excluded
        var File = Java.use("java.io.File");
        var originalCreateNewFile = File.createNewFile;
        
        File.createNewFile.implementation = function() {
            var path = this.getAbsolutePath();
            
            // Check if file is in nobackup directory
            if (path.includes("/no_backup/") || path.includes("nobackup")) {
                console.log("[+] File created in no-backup location: " + path);
                console.log("[!] SENSITIVE FILE EXCLUDED FROM BACKUP");
            }
            
            return originalCreateNewFile.call(this);
        };
        
    } catch(e) {
        console.log("[-] File backup monitoring failed");
    }
});`}
                />

                <h4 className="text-lg font-medium text-cybr-secondary">Backup Security Assessment Tool</h4>
                <CodeExample
                  language="python"
                  title="Comprehensive Backup Security Analysis"
                  code={`#!/usr/bin/env python3
"""
Android Backup Security Assessment Tool
"""

import xml.etree.ElementTree as ET
import tarfile
import os
import re
import json
from pathlib import Path

class BackupSecurityAnalyzer:
    def __init__(self, app_dir, backup_file=None):
        self.app_dir = Path(app_dir)
        self.backup_file = backup_file
        self.vulnerabilities = []
        self.backup_analysis = {}
        
    def analyze_manifest_backup_settings(self):
        """Analyze AndroidManifest.xml for backup configuration"""
        manifest_path = self.app_dir / "AndroidManifest.xml"
        
        if not manifest_path.exists():
            return
        
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Find application element
            app_elem = root.find('.//application')
            if app_elem is not None:
                # Check allowBackup setting
                allow_backup = app_elem.get('{http://schemas.android.com/apk/res/android}allowBackup')
                
                if allow_backup == 'true':
                    self.vulnerabilities.append({
                        'type': 'Backup Enabled',
                        'setting': 'android:allowBackup="true"',
                        'severity': 'HIGH',
                        'description': 'Application allows backup, potentially exposing sensitive data'
                    })
                
                # Check for backup agent
                backup_agent = app_elem.get('{http://schemas.android.com/apk/res/android}backupAgent')
                if backup_agent:
                    self.backup_analysis['backup_agent'] = backup_agent
                    self.vulnerabilities.append({
                        'type': 'Custom Backup Agent',
                        'agent': backup_agent,
                        'severity': 'MEDIUM',
                        'description': 'Custom backup agent requires security review'
                    })
                
                # Check for full backup content rules
                full_backup_content = app_elem.get('{http://schemas.android.com/apk/res/android}fullBackupContent')
                if full_backup_content:
                    self.backup_analysis['backup_rules'] = full_backup_content
                
                # Check for data extraction rules (Android 12+)
                data_extraction_rules = app_elem.get('{http://schemas.android.com/apk/res/android}dataExtractionRules')
                if data_extraction_rules:
                    self.backup_analysis['extraction_rules'] = data_extraction_rules
                
        except ET.ParseError as e:
            print(f"[-] Error parsing AndroidManifest.xml: {e}")
    
    def analyze_backup_rules(self):
        """Analyze backup rules configuration"""
        # Look for backup rules files
        backup_rule_files = []
        backup_rule_files.extend(list(self.app_dir.rglob('*backup*.xml')))
        backup_rule_files.extend(list(self.app_dir.rglob('*extraction*.xml')))
        
        for rule_file in backup_rule_files:
            try:
                tree = ET.parse(rule_file)
                root = tree.getroot()
                
                # Analyze include/exclude rules
                includes = root.findall('.//include')
                excludes = root.findall('.//exclude')
                
                if not excludes:
                    self.vulnerabilities.append({
                        'type': 'No Backup Exclusions',
                        'file': str(rule_file),
                        'severity': 'MEDIUM',
                        'description': 'No exclusion rules found - all data may be backed up'
                    })
                
                # Check for overly broad includes
                for include in includes:
                    domain = include.get('domain')
                    path = include.get('path')
                    
                    if domain == 'root' and path == '/':
                        self.vulnerabilities.append({
                            'type': 'Overly Broad Backup Include',
                            'rule': f'domain="{domain}" path="{path}"',
                            'severity': 'HIGH',
                            'description': 'Backup includes entire application data'
                        })
                
                # Check for sensitive path exclusions
                sensitive_paths = ['database', 'shared_prefs', 'files']
                excluded_paths = [exclude.get('path', '') for exclude in excludes]
                
                for sensitive_path in sensitive_paths:
                    if not any(sensitive_path in path for path in excluded_paths):
                        self.vulnerabilities.append({
                            'type': f'Sensitive Path Not Excluded: {sensitive_path}',
                            'severity': 'MEDIUM',
                            'description': f'{sensitive_path} directory not excluded from backup'
                        })
                
            except ET.ParseError as e:
                print(f"[-] Error parsing backup rules {rule_file}: {e}")
    
    def analyze_backup_agent_code(self):
        """Analyze custom backup agent implementation"""
        java_files = list(self.app_dir.rglob('*.java'))
        java_files.extend(list(self.app_dir.rglob('*.kt')))
        
        for java_file in java_files:
            try:
                with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Check for BackupAgent implementation
                if 'extends BackupAgent' in content or 'BackupAgentHelper' in content:
                    # Look for security issues in backup implementation
                    if 'onBackup' in content:
                        # Check for sensitive data handling
                        if re.search(r'password|secret|token|key', content, re.IGNORECASE):
                            self.vulnerabilities.append({
                                'type': 'Sensitive Data in Backup Agent',
                                'file': str(java_file),
                                'severity': 'HIGH',
                                'description': 'Backup agent may handle sensitive data'
                            })
                    
                    # Check for encryption in backup
                    if 'encrypt' not in content.lower() and 'cipher' not in content.lower():
                        self.vulnerabilities.append({
                            'type': 'Unencrypted Backup Implementation',
                            'file': str(java_file),
                            'severity': 'HIGH',
                            'description': 'Backup agent does not appear to encrypt data'
                        })
                
            except Exception as e:
                print(f"[-] Error analyzing {java_file}: {e}")
    
    def analyze_adb_backup(self):
        """Analyze ADB backup file if provided"""
        if not self.backup_file or not os.path.exists(self.backup_file):
            return
        
        print(f"[+] Analyzing ADB backup file: {self.backup_file}")
        
        try:
            # Extract backup file (simplified - real implementation would handle AB format)
            if self.backup_file.endswith('.tar') or tarfile.is_tarfile(self.backup_file):
                with tarfile.open(self.backup_file, 'r') as tar:
                    members = tar.getmembers()
                    
                    # Analyze backup contents
                    database_files = [m for m in members if m.name.endswith('.db')]
                    shared_prefs = [m for m in members if 'shared_prefs' in m.name]
                    
                    if database_files:
                        self.vulnerabilities.append({
                            'type': 'Databases in Backup',
                            'files': [m.name for m in database_files],
                            'severity': 'CRITICAL',
                            'description': 'SQLite databases present in backup'
                        })
                    
                    if shared_prefs:
                        self.vulnerabilities.append({
                            'type': 'SharedPreferences in Backup',
                            'files': [m.name for m in shared_prefs],
                            'severity': 'HIGH',
                            'description': 'SharedPreferences files present in backup'
                        })
                    
                    # Extract and analyze sensitive files
                    for member in members[:10]:  # Limit to first 10 files
                        if member.isfile() and member.size < 1024*1024:  # Less than 1MB
                            try:
                                extracted = tar.extractfile(member)
                                if extracted:
                                    content = extracted.read().decode('utf-8', errors='ignore')
                                    
                                    # Search for sensitive patterns
                                    if re.search(r'password|secret|token|key', content, re.IGNORECASE):
                                        self.vulnerabilities.append({
                                            'type': 'Sensitive Data in Backup File',
                                            'file': member.name,
                                            'severity': 'CRITICAL',
                                            'description': 'Backup file contains sensitive data'
                                        })
                            except:
                                pass
        
        except Exception as e:
            print(f"[-] Error analyzing backup file: {e}")
    
    def check_cloud_backup_integration(self):
        """Check for Google Cloud Backup integration"""
        java_files = list(self.app_dir.rglob('*.java'))
        java_files.extend(list(self.app_dir.rglob('*.kt')))
        
        for java_file in java_files:
            try:
                with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Check for Google Backup Transport
                if 'GmsBackupTransport' in content or 'CloudBackup' in content:
                    self.vulnerabilities.append({
                        'type': 'Google Cloud Backup Integration',
                        'file': str(java_file),
                        'severity': 'MEDIUM',
                        'description': 'Application uses Google Cloud Backup - review data handling'
                    })
                
                # Check for custom cloud backup solutions
                cloud_patterns = [
                    r'aws.*backup', r'azure.*backup', r'google.*drive.*backup',
                    r'dropbox.*backup', r'onedrive.*backup'
                ]
                
                for pattern in cloud_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.vulnerabilities.append({
                            'type': 'Third-party Cloud Backup',
                            'file': str(java_file),
                            'pattern': pattern,
                            'severity': 'MEDIUM',
                            'description': 'Third-party cloud backup integration found'
                        })
                        break
                
            except Exception as e:
                print(f"[-] Error analyzing {java_file}: {e}")
    
    def analyze(self):
        """Perform comprehensive backup security analysis"""
        print(f"[+] Starting backup security analysis: {self.app_dir}")
        
        self.analyze_manifest_backup_settings()
        self.analyze_backup_rules()
        self.analyze_backup_agent_code()
        self.analyze_adb_backup()
        self.check_cloud_backup_integration()
        
        self.generate_report()
    
    def generate_report(self):
        """Generate backup security assessment report"""
        print("\\n" + "="*60)
        print("BACKUP SECURITY ANALYSIS REPORT")
        print("="*60)
        
        if self.backup_analysis:
            print("Backup Configuration:")
            for key, value in self.backup_analysis.items():
                print(f"  {key}: {value}")
            print()
        
        if not self.vulnerabilities:
            print("[+] No backup security issues found")
            return
        
        # Count by severity
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"Total Issues: {len(self.vulnerabilities)}")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_counts:
                print(f"{severity}: {severity_counts[severity]}")
        print()
        
        # Detailed findings
        for vuln in sorted(self.vulnerabilities, 
                          key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}[x['severity']], 
                          reverse=True):
            print(f"[{vuln['severity']}] {vuln['type']}")
            for key, value in vuln.items():
                if key not in ['type', 'severity']:
                    if isinstance(value, list) and len(value) > 3:
                        print(f"  {key}: {value[:3]} ... (and {len(value)-3} more)")
                    else:
                        print(f"  {key}: {value}")
            print()

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python backup_analyzer.py <app_directory> [backup_file.tar]")
        sys.exit(1)
    
    backup_file = sys.argv[2] if len(sys.argv) > 2 else None
    analyzer = BackupSecurityAnalyzer(sys.argv[1], backup_file)
    analyzer.analyze()`}
                />
              </div>
            </TabsContent>
          </Tabs>

          <div className="mt-6 p-4 bg-cybr-muted/20 rounded-lg">
            <h4 className="font-medium text-cybr-accent mb-2">Android Storage Security Best Practices</h4>
            <ul className="list-disc pl-6 space-y-1 text-sm">
              <li><strong>Internal Storage</strong>: Use internal storage for sensitive data with proper file permissions (600)</li>
              <li><strong>SharedPreferences</strong>: Never store sensitive data in plain text; use EncryptedSharedPreferences</li>
              <li><strong>SQLite Encryption</strong>: Use SQLCipher or Android's encrypted database solutions</li>
              <li><strong>External Storage</strong>: Avoid storing sensitive data; use scoped storage (Android 10+)</li>
              <li><strong>Android Keystore</strong>: Leverage hardware-backed security with user authentication requirements</li>
              <li><strong>Backup Configuration</strong>: Set allowBackup="false" or configure proper exclusion rules</li>
              <li><strong>Data Classification</strong>: Implement proper data classification and storage strategies</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AndroidStorageAnalysis;
