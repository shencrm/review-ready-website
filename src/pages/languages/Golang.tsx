
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import { Link } from 'react-router-dom';
import { Golang } from 'lucide-react';

const GolangPage = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">Golang Security</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              Security vulnerabilities and best practices for Go applications.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">Command Injection</h2>
                <p className="mb-4">
                  Even though Go is a compiled language, command injection vulnerabilities can still occur when using the os/exec package improperly.
                </p>
                
                <CodeExample
                  language="go"
                  title="Command Injection Vulnerability"
                  code={`// VULNERABLE: Using user input directly in command
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func handlePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	
	// VULNERABLE: Directly using user input in command string
	cmd := exec.Command("sh", "-c", "ping -c 1 " + host)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, "%s", output)
}

// An attacker could use: ?host=google.com; rm -rf /`}
                />
                
                <CodeExample
                  language="go"
                  title="Secure Command Execution"
                  code={`// SECURE: Using exec.Command correctly with separate arguments
package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
)

func handlePingSafely(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	
	// Validate input with regex for hostnames
	valid := regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\\.[a-zA-Z]{2,})+$")
	if !valid.MatchString(host) {
		http.Error(w, "Invalid hostname", http.StatusBadRequest)
		return
	}
	
	// SECURE: Pass arguments separately - no shell is invoked
	cmd := exec.Command("ping", "-c", "1", host)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, "%s", output)
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">SQL Injection in Go</h2>
                <p className="mb-4">
                  SQL injection can happen in Go applications when user inputs are concatenated directly into SQL queries.
                </p>
                
                <CodeExample
                  language="go"
                  title="SQL Injection Vulnerability"
                  code={`// VULNERABLE: String concatenation in SQL queries
package main

import (
	"database/sql"
	"fmt"
	"net/http"
	
	_ "github.com/go-sql-driver/mysql"
)

func getUserDetails(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	
	db, err := sql.Open("mysql", "user:password@tcp(127.0.0.1:3306)/dbname")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()
	
	// VULNERABLE: Direct string concatenation
	query := "SELECT id, name, email FROM users WHERE username = '" + username + "'"
	rows, err := db.Query(query)
	
	// Process results...
}

// Attacker could use: ?username=admin' OR '1'='1`}
                />
                
                <CodeExample
                  language="go"
                  title="Secure SQL Query"
                  code={`// SECURE: Using parameterized queries
package main

import (
	"database/sql"
	"net/http"
	
	_ "github.com/go-sql-driver/mysql"
)

func getUserDetailsSafely(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	
	db, err := sql.Open("mysql", "user:password@tcp(127.0.0.1:3306)/dbname")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()
	
	// SECURE: Using parameterized query
	query := "SELECT id, name, email FROM users WHERE username = ?"
	rows, err := db.Query(query, username)
	
	// Process results...
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">File Path Traversal</h2>
                <p className="mb-4">
                  Path traversal vulnerabilities allow attackers to access files outside intended directories.
                </p>
                
                <CodeExample
                  language="go"
                  title="Path Traversal Vulnerability"
                  code={`// VULNERABLE: Unsafe file path handling
package main

import (
	"io/ioutil"
	"net/http"
	"path"
)

func serveFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	
	// VULNERABLE: Doesn't sanitize path or check for traversal
	filepath := path.Join("./files/", filename)
	
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	w.Write(data)
}

// Attacker could use: ?filename=../../../etc/passwd`}
                />
                
                <CodeExample
                  language="go"
                  title="Secure File Access"
                  code={`// SECURE: Preventing path traversal
package main

import (
	"io/ioutil"
	"net/http"
	"path"
	"path/filepath"
	"strings"
)

func serveFileSafely(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	
	// SECURE: Sanitize filename - remove slashes and dots
	sanitized := filepath.Base(filename)
	
	// SECURE: Explicitly check file is in allowed directory
	filepath := path.Join("./files/", sanitized)
	absPath, err := filepath.Abs(filepath)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	// SECURE: Ensure path is within intended directory
	filesDir, err := filepath.Abs("./files")
	if err != nil || !strings.HasPrefix(absPath, filesDir) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	w.Write(data)
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Secure HTTP Headers in Go</h2>
                <p className="mb-4">
                  Proper HTTP header configuration is important to protect Go web applications.
                </p>
                
                <CodeExample
                  language="go"
                  title="Implementing Security Headers"
                  code={`// SECURE: Adding security HTTP headers
package main

import (
	"net/http"
)

func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer-when-downgrade")
		w.Header().Set("Feature-Policy", "camera 'none'; microphone 'none'")
		
		// HTTPS only cookies
		w.Header().Set("Set-Cookie", "HttpOnly; Secure; SameSite=Strict")
		
		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	
	// Register routes
	mux.HandleFunc("/", homeHandler)
	
	// Wrap with security middleware
	http.ListenAndServe(":8080", securityMiddleware(mux))
}`}
                />
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">Common Golang Security Issues</h3>
                  <ul className="space-y-2 pl-4 text-cybr-foreground/80">
                    <li>Command Injection</li>
                    <li>SQL Injection</li>
                    <li>Path Traversal</li>
                    <li>Insecure Deserialization</li>
                    <li>Race Conditions</li>
                    <li>Concurrent Access Issues</li>
                    <li>Improper TLS Configuration</li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Golang Security Tools</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/securego/gosec" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">gosec</a></li>
                    <li><a href="https://github.com/golang/lint" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">golint</a></li>
                    <li><a href="https://github.com/dominikh/go-tools" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">staticcheck</a></li>
                    <li><a href="https://github.com/sonatype-nexus-community/nancy" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">nancy (dependency checker)</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Go Security Resources</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://blog.golang.org/go-security-release-process" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Go Security Release Process</a></li>
                    <li><a href="https://golang.org/doc/security" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Go Security Policy</a></li>
                    <li><a href="https://github.com/OWASP/Go-SCP" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Go Secure Coding Practices</a></li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
      
      <Footer />
    </div>
  );
};

export default GolangPage;
