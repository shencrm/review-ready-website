
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import { Link } from 'react-router-dom';
import { ArrowRight, Shield, Lock, Terminal, FileCode } from 'lucide-react';

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
                  Although Go is a compiled language, command injection vulnerabilities can still occur when improperly using the os/exec package.
                </p>
                
                <CodeExample
                  language="go"
                  title="Command Injection Vulnerability"
                  code={`// Vulnerable: Using user input directly in command
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func handlePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	
	// Vulnerable: Direct use of user input in command string
	cmd := exec.Command("sh", "-c", "ping -c 1 " + host)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, "%s", output)
}

// Attacker can use: ?host=google.com; rm -rf /`}
                />
                
                <CodeExample
                  language="go"
                  title="Secure Command Execution"
                  code={`// Secure: Proper use of exec.Command with separate arguments
package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
)

func handlePingSafely(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	
	// Input validation with regex for hostnames
	valid := regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\\.[a-zA-Z]{2,})+$")
	if !valid.MatchString(host) {
		http.Error(w, "Invalid hostname", http.StatusBadRequest)
		return
	}
	
	// Secure: Pass arguments separately - no shell is invoked
	cmd := exec.Command("ping", "-c", "1", host)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, "%s", output)
}`}
                />

                <CodeExample
                  language="go"
                  title="Advanced Command Injection Solution"
                  code={`// More comprehensive solution with extended validation and logging
package main

import (
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// List of allowed commands to execute
var allowedCommands = map[string]bool{
	"ping":    true,
	"nslookup": true,
	"dig":      true,
}

func executeCommand(command string, args ...string) ([]byte, error) {
	// Validate the command
	if !allowedCommands[command] {
		return nil, fmt.Errorf("Unauthorized command: %s", command)
	}
	
	// Log the executing command
	log.Printf("Executing command: %s %s", command, strings.Join(args, " "))
	
	// Set command timeout
	cmd := exec.Command(command, args...)
	
	// Create a channel for timeout
	done := make(chan error, 1)
	
	// Run the command in separate goroutine
	var output []byte
	var err error
	
	go func() {
		output, err = cmd.CombinedOutput()
		done <- err
	}()
	
	// Set a 5 second timeout
	select {
	case <-time.After(5 * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return nil, fmt.Errorf("Command execution timed out")
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("Command execution error: %v", err)
		}
		return output, nil
	}
}

func safeNetworkToolHandler(w http.ResponseWriter, r *http.Request) {
	// Validate user (simple example)
	apiKey := r.Header.Get("X-API-Key")
	if !isValidAPIKey(apiKey) {
		http.Error(w, "Authorization denied", http.StatusUnauthorized)
		return
	}
	
	// Get parameters
	tool := r.URL.Query().Get("tool")
	host := r.URL.Query().Get("host")
	
	// Validate tool
	if !allowedCommands[tool] {
		http.Error(w, "Unauthorized tool", http.StatusBadRequest)
		return
	}
	
	// Validate hostname format with strict regex
	validHost := regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\\.[a-zA-Z0-9]{2,})+$")
	if !validHost.MatchString(host) {
		http.Error(w, "Invalid hostname", http.StatusBadRequest)
		return
	}
	
	// Prepare tool args map
	toolArgs := map[string][]string{
		"ping":     {"-c", "4", host},
		"nslookup": {host},
		"dig":      {host},
	}
	
	// Execute command using secure function
	output, err := executeCommand(tool, toolArgs[tool]...)
	if err != nil {
		log.Printf("Error: %v", err)
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Return output with appropriate content type
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s", output)
}

// Function to validate API key
func isValidAPIKey(key string) bool {
	validKeys := map[string]bool{
		"api_key_123": true,
		"api_key_456": true,
	}
	return validKeys[key]
}

func main() {
	// Set up path and listening
	http.HandleFunc("/api/network-tool", safeNetworkToolHandler)
	
	log.Println("Server listening at :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">SQL Injection in Go</h2>
                <p className="mb-4">
                  SQL injection can occur in Go applications when user inputs are directly concatenated into SQL queries.
                </p>
                
                <CodeExample
                  language="go"
                  title="SQL Injection Vulnerability"
                  code={`// Vulnerable: String concatenation in SQL queries
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
	
	// Vulnerable: Direct string concatenation
	query := "SELECT id, name, email FROM users WHERE username = '" + username + "'"
	rows, err := db.Query(query)
	
	// Process results...
}

// Attacker can use: ?username=admin' OR '1'='1`}
                />
                
                <CodeExample
                  language="go"
                  title="Secure SQL Query"
                  code={`// Secure: Using parameterized queries
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
	
	// Secure: Using parameterized query
	query := "SELECT id, name, email FROM users WHERE username = ?"
	rows, err := db.Query(query, username)
	
	// Process results...
}`}
                />

                <CodeExample
                  language="go"
                  title="More Secure Database Access Implementation"
                  code={`// More secure: Using prepared statements, connection pooling, and error logging
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// User model
type User struct {
	ID       int    \`json:"id"\`
	Username string \`json:"username"\`
	Name     string \`json:"name"\`
	Email    string \`json:"email"\`
}

// Database manager
type DBManager struct {
	db *sql.DB
}

// Create new database manager
func NewDBManager() (*DBManager, error) {
	// Get connection details from environment variables
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbName := os.Getenv("DB_NAME")
	
	if dbUser == "" || dbPassword == "" || dbHost == "" || dbName == "" {
		return nil, fmt.Errorf("Missing database connection details")
	}
	
	// Build DSN string
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true", dbUser, dbPassword, dbHost, dbName)
	
	// Open database connection
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("Error opening database connection: %v", err)
	}
	
	// Configure connection limits
	db.SetMaxOpenConns(25) // Limit to specific number of open connections
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)
	
	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("Error testing database connection: %v", err)
	}
	
	return &DBManager{db: db}, nil
}

// Close connections
func (m *DBManager) Close() error {
	return m.db.Close()
}

// Get user by username
func (m *DBManager) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	// Create prepared statement
	stmt, err := m.db.PrepareContext(ctx, "SELECT id, username, name, email FROM users WHERE username = ?")
	if err != nil {
		return nil, fmt.Errorf("Error preparing query: %v", err)
	}
	defer stmt.Close()
	
	// Define user
	var user User
	
	// Execute query with parameters
	err = stmt.QueryRowContext(ctx, username).Scan(&user.ID, &user.Username, &user.Name, &user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No results
		}
		return nil, fmt.Errorf("Error executing query: %v", err)
	}
	
	return &user, nil
}

// Get users with various filters
func (m *DBManager) GetUsers(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]User, error) {
	// Build base query
	query := "SELECT id, username, name, email FROM users WHERE 1=1"
	var args []interface{}
	
	// Add filters if any
	if nameFilter, ok := filters["name"]; ok && nameFilter != "" {
		query += " AND name LIKE ?"
		args = append(args, "%" + nameFilter.(string) + "%")
	}
	
	if emailFilter, ok := filters["email"]; ok && emailFilter != "" {
		query += " AND email = ?"
		args = append(args, emailFilter)
	}
	
	// Add limit and offset
	query += " LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	
	// Prepare query
	stmt, err := m.db.PrepareContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("Error preparing query: %v", err)
	}
	defer stmt.Close()
	
	// Execute query
	rows, err := stmt.QueryContext(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("Error executing query: %v", err)
	}
	defer rows.Close()
	
	// Collect results
	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.Name, &user.Email); err != nil {
			return nil, fmt.Errorf("Error scanning row: %v", err)
		}
		users = append(users, user)
	}
	
	// Check for errors during row iteration
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("Error reading rows: %v", err)
	}
	
	return users, nil
}

// HTTP handler for getting a user
func (m *DBManager) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	// Extract username from parameters
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	
	// Get user from database
	user, err := m.GetUserByUsername(ctx, username)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		http.Error(w, "Error retrieving data", http.StatusInternalServerError)
		return
	}
	
	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	
	// Return user as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		log.Printf("Error encoding user to JSON: %v", err)
		http.Error(w, "Error processing response", http.StatusInternalServerError)
	}
}

func main() {
	// Create database manager
	dbManager, err := NewDBManager()
	if err != nil {
		log.Fatalf("Error initializing database manager: %v", err)
	}
	defer dbManager.Close()
	
	// Set up API path
	http.HandleFunc("/api/user", dbManager.HandleGetUser)
	
	// Start server
	log.Println("Server listening at :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Path Traversal</h2>
                <p className="mb-4">
                  Path traversal vulnerabilities allow attackers to access files outside of intended directories.
                </p>
                
                <CodeExample
                  language="go"
                  title="Path Traversal Vulnerability"
                  code={`// Vulnerable: Unsafe handling of file path
package main

import (
	"io/ioutil"
	"net/http"
	"path"
)

func serveFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	
	// Vulnerable: Not sanitizing path or checking for traversal
	filepath := path.Join("./files/", filename)
	
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	w.Write(data)
}

// Attacker can use: ?filename=../../../etc/passwd`}
                />
                
                <CodeExample
                  language="go"
                  title="Secure File Access"
                  code={`// Secure: Preventing path traversal
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
	
	// Secure: Sanitize filename - strip slashes and dots
	sanitized := filepath.Base(filename)
	
	// Secure: Explicitly check that file is in allowed directory
	filepath := path.Join("./files/", sanitized)
	absPath, err := filepath.Abs(filepath)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	// Secure: Ensure path is within intended directory
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

                <CodeExample
                  language="go"
                  title="Advanced Secure Filesystem"
                  code={`// Advanced file handling with virtual directories and sanitization
package main

import (
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// File manager with secure mapping
type SafeFileManager struct {
	// Physical files directory
	baseDir string
	
	// Mapping of virtual directories to physical directories
	virtualDirs map[string]string
	
	// Allowed file types
	allowedExtensions map[string]bool
}

// Create new file manager
func NewSafeFileManager(baseDir string) *SafeFileManager {
	// Ensure base directory exists
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		os.MkdirAll(baseDir, 0755)
	}
	
	return &SafeFileManager{
		baseDir: baseDir,
		virtualDirs: map[string]string{
			"public": filepath.Join(baseDir, "public"),
			"images": filepath.Join(baseDir, "images"),
			"docs":   filepath.Join(baseDir, "documents"),
		},
		allowedExtensions: map[string]bool{
			".txt":  true,
			".pdf":  true,
			".png":  true,
			".jpg":  true,
			".jpeg": true,
			".gif":  true,
			".html": true,
			".css":  true,
			".js":   true,
		},
	}
}

// Initialize manager and create directories
func (sfm *SafeFileManager) Init() error {
	// Create all virtual directories if they don't exist
	for _, dir := range sfm.virtualDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("Error creating directory %s: %v", dir, err)
			}
		}
	}
	return nil
}

// Validate and map virtual path to secure physical path
func (sfm *SafeFileManager) ResolvePath(virtualPath string) (string, error) {
	// Parse virtual path
	parts := strings.SplitN(strings.Trim(virtualPath, "/"), "/", 2)
	if len(parts) == 0 {
		return "", fmt.Errorf("Empty path")
	}
	
	// Get virtual directory
	virtualDir := parts[0]
	physicalDir, exists := sfm.virtualDirs[virtualDir]
	if !exists {
		return "", fmt.Errorf("Unknown virtual directory: %s", virtualDir)
	}
	
	// Handle empty path
	if len(parts) == 1 || parts[1] == "" {
		return physicalDir, nil
	}
	
	// Check file extension
	filePath := parts[1]
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext != "" && !sfm.allowedExtensions[ext] {
		return "", fmt.Errorf("Unauthorized file type: %s", ext)
	}
	
	// Ensure no path traversal
	cleanedPath := filepath.Clean(filepath.Join(physicalDir, filepath.Clean(filePath)))
	if !strings.HasPrefix(cleanedPath, physicalDir) {
		return "", fmt.Errorf("Path traversal attempt")
	}
	
	return cleanedPath, nil
}

// Serve file
func (sfm *SafeFileManager) ServeFile(w http.ResponseWriter, r *http.Request) {
	// Get path from URL
	requestPath := r.URL.Path
	
	// Handle special case for root path
	if requestPath == "/" || requestPath == "" {
		http.Error(w, "File path required", http.StatusBadRequest)
		return
	}
	
	// Strip "/files" from beginning of path if it exists
	requestPath = strings.TrimPrefix(requestPath, "/files")
	requestPath = strings.TrimPrefix(requestPath, "/")
	
	// Validate and resolve the path
	physicalPath, err := sfm.ResolvePath(requestPath)
	if err != nil {
		log.Printf("Path validation error: %v", err)
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	// Check if file exists
	fileInfo, err := os.Stat(physicalPath)
	if os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	} else if err != nil {
		log.Printf("File access error: %v", err)
		http.Error(w, "System error", http.StatusInternalServerError)
		return
	}
	
	// If it's a directory, deny request or show listing
	if fileInfo.IsDir() {
		http.Error(w, "Cannot display directories", http.StatusForbidden)
		return
	}
	
	// Open the file
	file, err := os.Open(physicalPath)
	if err != nil {
		log.Printf("Error opening file: %v", err)
		http.Error(w, "Error accessing file", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	// Determine MIME type
	contentType := mime.TypeByExtension(filepath.Ext(physicalPath))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	
	// Set HTTP headers
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "inline; filename="+filepath.Base(physicalPath))
	w.Header().Set("Cache-Control", "public, max-age=86400") // Cache for one day
	w.Header().Set("Last-Modified", fileInfo.ModTime().UTC().Format(http.TimeFormat))
	
	// Send content
	http.ServeContent(w, r, filepath.Base(physicalPath), fileInfo.ModTime(), file)
}

// Upload file
func (sfm *SafeFileManager) HandleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// Limit form size to 10MB
	r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "File too large or invalid format", http.StatusBadRequest)
		return
	}
	
	// Get file from form
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Validate file type
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if !sfm.allowedExtensions[ext] {
		http.Error(w, "Unauthorized file type", http.StatusForbidden)
		return
	}
	
	// Create safe filename
	safeFilename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), sfm.sanitizeFilename(header.Filename))
	
	// Get destination directory from form
	destDir := r.FormValue("directory")
	physicalDir, exists := sfm.virtualDirs[destDir]
	if !exists {
		http.Error(w, "Invalid destination directory", http.StatusBadRequest)
		return
	}
	
	// Create destination file path
	destPath := filepath.Join(physicalDir, safeFilename)
	
	// Create destination file
	outFile, err := os.Create(destPath)
	if err != nil {
		log.Printf("Error creating destination file: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()
	
	// Copy contents
	_, err = io.Copy(outFile, file)
	if err != nil {
		log.Printf("Error writing file: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// Send successful response
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, \`{"success": true, "filename": "%s", "path": "%s/%s"}\`, 
		safeFilename, destDir, safeFilename)
}

// Sanitize filename
func (sfm *SafeFileManager) sanitizeFilename(filename string) string {
	// Take only base name
	filename = filepath.Base(filename)
	
	// Replace dangerous characters
	replacer := strings.NewReplacer(
		" ", "_",
		"\\", "",
		"/", "",
		":", "",
		"*", "",
		"?", "",
		"\"", "",
		"<", "",
		">", "",
		"|", "",
		";", "",
		"&", "",
	)
	
	return replacer.Replace(filename)
}

func main() {
	// Create secure file manager
	fileManager := NewSafeFileManager("./storage")
	if err := fileManager.Init(); err != nil {
		log.Fatalf("Error initializing file manager: %v", err)
	}
	
	// Set up paths
	http.HandleFunc("/files/", fileManager.ServeFile)
	http.HandleFunc("/upload", fileManager.HandleUpload)
	
	// Start server
	log.Println("Server listening at :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Secure HTTP Headers in Go</h2>
                <p className="mb-4">
                  Properly configuring HTTP headers is important for protecting Go web applications.
                </p>
                
                <CodeExample
                  language="go"
                  title="Implementing Security Headers"
                  code={`// Secure: Adding security HTTP headers
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
		
		// HTTPS-only cookies
		w.Header().Set("Set-Cookie", "HttpOnly; Secure; SameSite=Strict")
		
		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	
	// Register paths
	mux.HandleFunc("/", homeHandler)
	
	// Wrap with security middleware
	http.ListenAndServe(":8080", securityMiddleware(mux))
}`}
                />

                <CodeExample
                  language="go"
                  title="Advanced Security Middleware Implementation"
                  code={`// Comprehensive security middleware implementation with advanced options
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"strings"
	"time"
)

// Environment options
type Environment string
const (
	Development Environment = "development"
	Production  Environment = "production"
	Testing     Environment = "testing"
)

// Security configuration options
type SecurityOptions struct {
	Environment Environment
	
	// Security headers
	EnableCSP            bool
	EnableXSSProtection  bool
	EnableFrameOptions   bool
	EnableHSTS           bool
	
	// TLS options
	EnableTLS            bool
	TLSCertFile          string
	TLSKeyFile           string
	
	// Rate Limiting
	EnableRateLimit      bool
	RequestsPerMinute    int
	
	// CORS
	EnableCORS           bool
	AllowedOrigins       []string
	AllowedMethods       []string
	AllowedHeaders       []string
	
	// Cookies
	CookiePrefix         string
	CookieDomain         string
	CookiePath           string
}

// Default security values
func DefaultSecurityOptions() SecurityOptions {
	return SecurityOptions{
		Environment:        Production,
		EnableCSP:          true,
		EnableXSSProtection: true,
		EnableFrameOptions: true,
		EnableHSTS:         true,
		EnableTLS:          false,
		EnableRateLimit:    true,
		RequestsPerMinute:  60,
		EnableCORS:         false,
		CookiePrefix:       "__Secure-",
		CookiePath:         "/",
	}
}

// Security manager
type SecurityManager struct {
	options SecurityOptions
	rateLimiter *RateLimiter
}

// Create security manager
func NewSecurityManager(options SecurityOptions) *SecurityManager {
	// Initialize rate limiter if enabled
	var limiter *RateLimiter
	if options.EnableRateLimit {
		limiter = NewRateLimiter(options.RequestsPerMinute)
	}
	
	return &SecurityManager{
		options: options,
		rateLimiter: limiter,
	}
}

// Security middleware function
func (sm *SecurityManager) SecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Rate Limiting
		if sm.options.EnableRateLimit {
			clientIP := r.RemoteAddr
			if !sm.rateLimiter.AllowRequest(clientIP) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "Too many requests, try again later", http.StatusTooManyRequests)
				return
			}
		}
		
		// Set security headers
		sm.setSecurityHeaders(w, r)
		
		// CORS
		if sm.options.EnableCORS {
			origin := r.Header.Get("Origin")
			if sm.isOriginAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", 
					strings.Join(sm.options.AllowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", 
					strings.Join(sm.options.AllowedHeaders, ", "))
				w.Header().Set("Access-Control-Max-Age", "86400")
				
				// Handle preflight requests
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusOK)
					return
				}
			}
		}
		
		// Add security info to context
		ctx := context.WithValue(r.Context(), "security", map[string]interface{}{
			"environment": sm.options.Environment,
			"secure": r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		})
		
		// Continue to next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Set security headers
func (sm *SecurityManager) setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	// Basic security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	
	// Content-Security-Policy
	if sm.options.EnableCSP {
		cspValue := "default-src 'self'; "
		
		// Additional CSP options based on environment
		if sm.options.Environment == Development {
			cspValue += "script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
		} else {
			cspValue += "script-src 'self'; style-src 'self';"
		}
		
		cspValue += "img-src 'self' data:; font-src 'self'; object-src 'none'; frame-src 'none';"
		w.Header().Set("Content-Security-Policy", cspValue)
	}
	
	// X-Frame-Options
	if sm.options.EnableFrameOptions {
		w.Header().Set("X-Frame-Options", "DENY")
	}
	
	// X-XSS-Protection
	if sm.options.EnableXSSProtection {
		w.Header().Set("X-XSS-Protection", "1; mode=block")
	}
	
	// HSTS - only for HTTPS connections
	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	if sm.options.EnableHSTS && isSecure && sm.options.Environment == Production {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	}
	
	// Additional headers
	w.Header().Set("Referrer-Policy", "no-referrer-when-downgrade")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
}

// Check if origin is allowed
func (sm *SecurityManager) isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}
	
	// If no allowed origins list, don't allow CORS
	if len(sm.options.AllowedOrigins) == 0 {
		return false
	}
	
	// Check if there's a * in the origins list (allow all)
	for _, allowed := range sm.options.AllowedOrigins {
		if allowed == "*" {
			return true
		}
		if allowed == origin {
			return true
		}
	}
	
	return false
}

// Set secure cookie
func (sm *SecurityManager) SetSecureCookie(w http.ResponseWriter, name, value string, maxAge int) {
	isSecure := sm.options.Environment == Production
	
	// Add security prefix if needed
	if isSecure && sm.options.CookiePrefix != "" {
		name = sm.options.CookiePrefix + name
	}
	
	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		Path:     sm.options.CookiePath,
		Domain:   sm.options.CookieDomain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteStrictMode,
	}
	
	http.SetCookie(w, &cookie)
}

// Request rate limiting mechanism
type RateLimiter struct {
	requestsPerMinute int
	clients           map[string]*ClientBucket
	cleanupInterval   time.Duration
	lastCleanup       time.Time
}

// Client request bucket
type ClientBucket struct {
	tokens    int
	lastRefill time.Time
}

// Create new rate limiter
func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	return &RateLimiter{
		requestsPerMinute: requestsPerMinute,
		clients:           make(map[string]*ClientBucket),
		cleanupInterval:   5 * time.Minute,
		lastCleanup:       time.Now(),
	}
}

// Check if request is allowed
func (rl *RateLimiter) AllowRequest(clientIP string) bool {
	// Periodic cleanup of old clients
	rl.performCleanupIfNeeded()
	
	// Get client bucket or create new one
	bucket, exists := rl.clients[clientIP]
	if !exists {
		bucket = &ClientBucket{
			tokens:     rl.requestsPerMinute,
			lastRefill: time.Now(),
		}
		rl.clients[clientIP] = bucket
	}
	
	// Calculate time since last token refresh
	now := time.Now()
	timePassed := now.Sub(bucket.lastRefill)
	
	// Refill tokens based on time passed
	tokensToAdd := int(timePassed.Minutes() * float64(rl.requestsPerMinute))
	if tokensToAdd > 0 {
		bucket.tokens = min(bucket.tokens+tokensToAdd, rl.requestsPerMinute)
		bucket.lastRefill = now
	}
	
	// Check if enough tokens
	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}
	
	return false
}

// Min function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Clean up old clients
func (rl *RateLimiter) performCleanupIfNeeded() {
	now := time.Now()
	if now.Sub(rl.lastCleanup) > rl.cleanupInterval {
		for ip, bucket := range rl.clients {
			// Remove clients inactive for more than 30 minutes
			if now.Sub(bucket.lastRefill) > 30*time.Minute {
				delete(rl.clients, ip)
			}
		}
		rl.lastCleanup = now
	}
}

// Example program with security
func main() {
	// Create security options
	options := DefaultSecurityOptions()
	options.AllowedOrigins = []string{"https://example.com", "https://api.example.com"}
	options.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE"}
	options.AllowedHeaders = []string{"Content-Type", "Authorization"}
	options.CookieDomain = "example.com"
	
	// TLS secure configuration
	options.EnableTLS = true
	options.TLSCertFile = "cert.pem"
	options.TLSKeyFile = "key.pem"
	
	// Create security manager
	securityManager := NewSecurityManager(options)
	
	// Create HTTP router
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Example of using secure cookie
		securityManager.SetSecureCookie(w, "session", "abc123", 3600)
		w.Write([]byte("Hello secure world!"))
	})
	
	// Apply security middleware
	secureHandler := securityManager.SecurityMiddleware(mux)
	
	// Start server with TLS if enabled
	if options.EnableTLS {
		// Secure TLS configuration
		tlsConfig := &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}
		
		// Configure HTTP server
		server := &http.Server{
			Addr:         ":8443",
			Handler:      secureHandler,
			TLSConfig:    tlsConfig,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
		
		log.Println("Secure server running at https://localhost:8443")
		log.Fatal(server.ListenAndServeTLS(options.TLSCertFile, options.TLSKeyFile))
		
	} else {
		// Regular hosting
		server := &http.Server{
			Addr:         ":8080",
			Handler:      secureHandler,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
		
		log.Println("Server running at http://localhost:8080")
		log.Fatal(server.ListenAndServe())
	}
}`}
                />
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">Common Security Issues in Golang</h3>
                  <ul className="space-y-2 pl-4 text-cybr-foreground/80">
                    <li>Command Injection</li>
                    <li>SQL Injection</li>
                    <li>Path Traversal</li>
                    <li>Insecure Deserialization</li>
                    <li>Race Conditions</li>
                    <li>Concurrency Access Issues</li>
                    <li>Improper TLS Configuration</li>
                    <li>Information Leakage Errors</li>
                    <li>Improper Handling of Sensitive Files</li>
                    <li>Shared Memory Contamination</li>
                    <li>Information Leakage in Errors</li>
                    <li>Insufficient Randomness</li>
                    <li>Inadequate User Input Validation</li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Golang Security Tools</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/securego/gosec" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">gosec</a></li>
                    <li><a href="https://github.com/golang/lint" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">golint</a></li>
                    <li><a href="https://github.com/dominikh/go-tools" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">staticcheck</a></li>
                    <li><a href="https://github.com/sonatype-nexus-community/nancy" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">nancy (dependency checker)</a></li>
                    <li><a href="https://github.com/golang/vuln" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">govulncheck</a></li>
                    <li><a href="https://github.com/quasilyte/go-ruleguard" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">ruleguard</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Go Security Resources</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://blog.golang.org/go-security-release-process" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Go Security Release Process</a></li>
                    <li><a href="https://golang.org/doc/security" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Go Security Policy</a></li>
                    <li><a href="https://github.com/OWASP/Go-SCP" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Go Secure Coding Practices</a></li>
                    <li><a href="https://golang.org/pkg/crypto/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Go Cryptography Package</a></li>
                    <li><a href="https://pkg.go.dev/golang.org/x/crypto" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Go Cryptography Extensions</a></li>
                  </ul>
                </div>

                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">Recommended Security Libraries</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/unrolled/secure" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">unrolled/secure</a></li>
                    <li><a href="https://github.com/gorilla/csrf" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">gorilla/csrf</a></li>
                    <li><a href="https://github.com/justinas/nosurf" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">justinas/nosurf</a></li>
                    <li><a href="https://github.com/golang-jwt/jwt" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">golang-jwt/jwt</a></li>
                    <li><a href="https://github.com/microcosm-cc/bluemonday" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">bluemonday (HTML sanitizer)</a></li>
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
