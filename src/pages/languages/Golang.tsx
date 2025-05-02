
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
            <h1 className="text-4xl font-bold mb-6">אבטחת Golang</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              פגיעויות אבטחה ושיטות עבודה מומלצות ליישומי Go.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">הזרקת פקודות (Command Injection)</h2>
                <p className="mb-4">
                  למרות ש-Go היא שפה מהודרת, פגיעויות הזרקת פקודות עדיין יכולות להתרחש בעת שימוש לא נכון בחבילת os/exec.
                </p>
                
                <CodeExample
                  language="go"
                  title="פגיעות הזרקת פקודות"
                  code={`// פגיע: שימוש בקלט משתמש ישירות בפקודה
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func handlePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	
	// פגיע: שימוש ישיר בקלט משתמש במחרוזת פקודה
	cmd := exec.Command("sh", "-c", "ping -c 1 " + host)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, "%s", output)
}

// תוקף יכול להשתמש ב-: ?host=google.com; rm -rf /`}
                />
                
                <CodeExample
                  language="go"
                  title="הרצת פקודה מאובטחת"
                  code={`// מאובטח: שימוש נכון ב-exec.Command עם ארגומנטים נפרדים
package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
)

func handlePingSafely(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	
	// אימות קלט עם ביטוי רגולרי לשמות מארחים
	valid := regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\\.[a-zA-Z]{2,})+$")
	if !valid.MatchString(host) {
		http.Error(w, "שם מארח לא חוקי", http.StatusBadRequest)
		return
	}
	
	// מאובטח: העברת ארגומנטים בנפרד - לא מופעלת מעטפת
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
                  title="פתרון הזרקת פקודות מתקדם יותר"
                  code={`// פתרון מקיף יותר עם אימות מורחב ורישום
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

// רשימת פקודות מותרות לביצוע
var allowedCommands = map[string]bool{
	"ping":    true,
	"nslookup": true,
	"dig":      true,
}

func executeCommand(command string, args ...string) ([]byte, error) {
	// אימות הפקודה
	if !allowedCommands[command] {
		return nil, fmt.Errorf("פקודה לא מורשית: %s", command)
	}
	
	// רישום הפקודה שמבוצעת
	log.Printf("ביצוע פקודה: %s %s", command, strings.Join(args, " "))
	
	// הגדרת פסק זמן לפקודה
	cmd := exec.Command(command, args...)
	
	// יצירת תעלה לפסק זמן
	done := make(chan error, 1)
	
	// הרץ את הפקודה בגורוטינה נפרדת
	var output []byte
	var err error
	
	go func() {
		output, err = cmd.CombinedOutput()
		done <- err
	}()
	
	// הגדרת פסק זמן של 5 שניות
	select {
	case <-time.After(5 * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return nil, fmt.Errorf("פסק זמן בביצוע הפקודה")
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("שגיאה בביצוע הפקודה: %v", err)
		}
		return output, nil
	}
}

func safeNetworkToolHandler(w http.ResponseWriter, r *http.Request) {
	// אימות המשתמש (פשוט לדוגמה)
	apiKey := r.Header.Get("X-API-Key")
	if !isValidAPIKey(apiKey) {
		http.Error(w, "הרשאה נדחתה", http.StatusUnauthorized)
		return
	}
	
	// קבלת פרמטרים
	tool := r.URL.Query().Get("tool")
	host := r.URL.Query().Get("host")
	
	// בדיקת תקפות הכלי
	if !allowedCommands[tool] {
		http.Error(w, "כלי לא מורשה", http.StatusBadRequest)
		return
	}
	
	// אימות פורמט שם המארח בהתאם לביטויים רגולריים מחמירים
	validHost := regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\\.[a-zA-Z0-9]{2,})+$")
	if !validHost.MatchString(host) {
		http.Error(w, "שם מארח לא חוקי", http.StatusBadRequest)
		return
	}
	
	// הכנת מפת כלים לארגומנטים
	toolArgs := map[string][]string{
		"ping":     {"-c", "4", host},
		"nslookup": {host},
		"dig":      {host},
	}
	
	// ביצוע הפקודה באמצעות הפונקציה המאובטחת
	output, err := executeCommand(tool, toolArgs[tool]...)
	if err != nil {
		log.Printf("שגיאה: %v", err)
		http.Error(w, fmt.Sprintf("שגיאה: %v", err), http.StatusInternalServerError)
		return
	}
	
	// החזרת הפלט עם כותרת תוכן מתאימה
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s", output)
}

// פונקציה לאימות מפתח API
func isValidAPIKey(key string) bool {
	validKeys := map[string]bool{
		"api_key_123": true,
		"api_key_456": true,
	}
	return validKeys[key]
}

func main() {
	// הגדרת הנתיב וההאזנה
	http.HandleFunc("/api/network-tool", safeNetworkToolHandler)
	
	log.Println("שרת מאזין בכתובת :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">הזרקת SQL ב-Go</h2>
                <p className="mb-4">
                  הזרקת SQL יכולה להתרחש ביישומי Go כאשר קלט משתמשים מקושר ישירות לשאילתות SQL.
                </p>
                
                <CodeExample
                  language="go"
                  title="פגיעות הזרקת SQL"
                  code={`// פגיע: שרשור מחרוזות בשאילתות SQL
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
	
	// פגיע: שרשור מחרוזת ישיר
	query := "SELECT id, name, email FROM users WHERE username = '" + username + "'"
	rows, err := db.Query(query)
	
	// עיבוד התוצאות...
}

// תוקף יכול להשתמש ב-: ?username=admin' OR '1'='1`}
                />
                
                <CodeExample
                  language="go"
                  title="שאילתת SQL מאובטחת"
                  code={`// מאובטח: שימוש בשאילתות עם פרמטרים
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
	
	// מאובטח: שימוש בשאילתה עם פרמטרים
	query := "SELECT id, name, email FROM users WHERE username = ?"
	rows, err := db.Query(query, username)
	
	// עיבוד התוצאות...
}`}
                />

                <CodeExample
                  language="go"
                  title="יישום מאובטח יותר של גישה למסד נתונים"
                  code={`// מאובטח יותר: שימוש ב-prepared statements, חיבורים מוגבלים, ורישום שגיאות
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

// מודל משתמש
type User struct {
	ID       int    \`json:"id"\`
	Username string \`json:"username"\`
	Name     string \`json:"name"\`
	Email    string \`json:"email"\`
}

// מנהל מסד נתונים
type DBManager struct {
	db *sql.DB
}

// יצירת מנהל מסד נתונים חדש
func NewDBManager() (*DBManager, error) {
	// קבל את פרטי ההתחברות מתוך משתני סביבה
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbName := os.Getenv("DB_NAME")
	
	if dbUser == "" || dbPassword == "" || dbHost == "" || dbName == "" {
		return nil, fmt.Errorf("פרטי התחברות חסרים למסד הנתונים")
	}
	
	// בניית מחרוזת DSN
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true", dbUser, dbPassword, dbHost, dbName)
	
	// פתיחת חיבור למסד הנתונים
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("שגיאה בפתיחת חיבור למסד הנתונים: %v", err)
	}
	
	// הגדרת מגבלות חיבור
	db.SetMaxOpenConns(25) // מגביל לאט ספציפי של חיבורים פתוחים
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)
	
	// בדיקת חיבור
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("שגיאה בבדיקת חיבור למסד הנתונים: %v", err)
	}
	
	return &DBManager{db: db}, nil
}

// סגירת חיבורים
func (m *DBManager) Close() error {
	return m.db.Close()
}

// קבלת משתמש לפי שם משתמש
func (m *DBManager) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	// יצירת prepared statement (מוכן מראש)
	stmt, err := m.db.PrepareContext(ctx, "SELECT id, username, name, email FROM users WHERE username = ?")
	if err != nil {
		return nil, fmt.Errorf("שגיאה בהכנת שאילתה: %v", err)
	}
	defer stmt.Close()
	
	// הגדרת משתמש
	var user User
	
	// ביצוע השאילתה עם הפרמטרים
	err = stmt.QueryRowContext(ctx, username).Scan(&user.ID, &user.Username, &user.Name, &user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // אין תוצאות
		}
		return nil, fmt.Errorf("שגיאה בביצוע השאילתה: %v", err)
	}
	
	return &user, nil
}

// קבלת משתמשים על פי פילטרים שונים
func (m *DBManager) GetUsers(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]User, error) {
	// בניית שאילתה בסיסית
	query := "SELECT id, username, name, email FROM users WHERE 1=1"
	var args []interface{}
	
	// הוספת פילטרים אם יש
	if nameFilter, ok := filters["name"]; ok && nameFilter != "" {
		query += " AND name LIKE ?"
		args = append(args, "%" + nameFilter.(string) + "%")
	}
	
	if emailFilter, ok := filters["email"]; ok && emailFilter != "" {
		query += " AND email = ?"
		args = append(args, emailFilter)
	}
	
	// הוספת מגבלה ודילוג
	query += " LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	
	// הכנת השאילתה
	stmt, err := m.db.PrepareContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("שגיאה בהכנת שאילתה: %v", err)
	}
	defer stmt.Close()
	
	// ביצוע השאילתה
	rows, err := stmt.QueryContext(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("שגיאה בביצוע השאילתה: %v", err)
	}
	defer rows.Close()
	
	// איסוף התוצאות
	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.Name, &user.Email); err != nil {
			return nil, fmt.Errorf("שגיאה בסריקת שורה: %v", err)
		}
		users = append(users, user)
	}
	
	// בדיקת שגיאות בזמן חזרה על השורות
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("שגיאה בקריאת שורות: %v", err)
	}
	
	return users, nil
}

// טיפול ב-HTTP לקבלת משתמש
func (m *DBManager) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	// חילוץ שם המשתמש מהפרמטרים
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "שם משתמש נדרש", http.StatusBadRequest)
		return
	}
	
	// יצירת הקשר עם פסק זמן
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	
	// קבלת משתמש ממסד הנתונים
	user, err := m.GetUserByUsername(ctx, username)
	if err != nil {
		log.Printf("שגיאה בקבלת משתמש: %v", err)
		http.Error(w, "שגיאה בקבלת הנתונים", http.StatusInternalServerError)
		return
	}
	
	if user == nil {
		http.Error(w, "משתמש לא נמצא", http.StatusNotFound)
		return
	}
	
	// החזרת המשתמש כ-JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		log.Printf("שגיאה בהמרת המשתמש ל-JSON: %v", err)
		http.Error(w, "שגיאה בעיבוד התגובה", http.StatusInternalServerError)
	}
}

func main() {
	// יצירת מנהל מסד נתונים
	dbManager, err := NewDBManager()
	if err != nil {
		log.Fatalf("שגיאה באתחול מנהל מסד הנתונים: %v", err)
	}
	defer dbManager.Close()
	
	// הגדרת נתיב ה-API
	http.HandleFunc("/api/user", dbManager.HandleGetUser)
	
	// הפעלת השרת
	log.Println("שרת מאזין בכתובת :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Path Traversal (טיול בנתיבים)</h2>
                <p className="mb-4">
                  פגיעויות path traversal מאפשרות לתוקפים לגשת לקבצים מחוץ לתיקיות המיועדות.
                </p>
                
                <CodeExample
                  language="go"
                  title="פגיעות Path Traversal"
                  code={`// פגיע: טיפול לא בטוח בנתיב קובץ
package main

import (
	"io/ioutil"
	"net/http"
	"path"
)

func serveFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	
	// פגיע: לא מנקה את הנתיב או בודק טיול
	filepath := path.Join("./files/", filename)
	
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		http.Error(w, "הקובץ לא נמצא", http.StatusNotFound)
		return
	}
	
	w.Write(data)
}

// תוקף יכול להשתמש ב-: ?filename=../../../etc/passwd`}
                />
                
                <CodeExample
                  language="go"
                  title="גישה מאובטחת לקבצים"
                  code={`// מאובטח: מניעת path traversal
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
	
	// מאובטח: סניטציה של שם הקובץ - הסרת לוכסנים ונקודות
	sanitized := filepath.Base(filename)
	
	// מאובטח: בדיקה מפורשת שהקובץ נמצא בתיקייה המותרת
	filepath := path.Join("./files/", sanitized)
	absPath, err := filepath.Abs(filepath)
	if err != nil {
		http.Error(w, "נתיב לא חוקי", http.StatusBadRequest)
		return
	}
	
	// מאובטח: וודא שהנתיב נמצא בתוך התיקייה המיועדת
	filesDir, err := filepath.Abs("./files")
	if err != nil || !strings.HasPrefix(absPath, filesDir) {
		http.Error(w, "הגישה נדחתה", http.StatusForbidden)
		return
	}
	
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		http.Error(w, "הקובץ לא נמצא", http.StatusNotFound)
		return
	}
	
	w.Write(data)
}`}
                />

                <CodeExample
                  language="go"
                  title="מערכת קבצים מאובטחת מתקדמת"
                  code={`// טיפול מתקדם בקבצים עם תיקיות וירטואליות וסניטציה
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

// מנהל קבצים עם מיפוי בטוח
type SafeFileManager struct {
	// תיקיית הקבצים הפיזית
	baseDir string
	
	// מיפוי של תיקיות וירטואליות לתיקיות פיזיות
	virtualDirs map[string]string
	
	// סוגי קבצים מותרים
	allowedExtensions map[string]bool
}

// יצירת מנהל קבצים חדש
func NewSafeFileManager(baseDir string) *SafeFileManager {
	// ודא שהתיקייה הבסיסית קיימת
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

// אתחול המנהל ויצירת תיקיות
func (sfm *SafeFileManager) Init() error {
	// יצירת כל התיקיות הווירטואליות אם הן לא קיימות
	for _, dir := range sfm.virtualDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("שגיאה ביצירת תיקייה %s: %v", dir, err)
			}
		}
	}
	return nil
}

// אימות ומיפוי נתיב וירטואלי לנתיב פיזי בטוח
func (sfm *SafeFileManager) ResolvePath(virtualPath string) (string, error) {
	// פירוק הנתיב הוירטואלי
	parts := strings.SplitN(strings.Trim(virtualPath, "/"), "/", 2)
	if len(parts) == 0 {
		return "", fmt.Errorf("נתיב ריק")
	}
	
	// קבלת התיקייה הוירטואלית
	virtualDir := parts[0]
	physicalDir, exists := sfm.virtualDirs[virtualDir]
	if !exists {
		return "", fmt.Errorf("תיקייה וירטואלית לא מוכרת: %s", virtualDir)
	}
	
	// טיפול בנתיב ריק
	if len(parts) == 1 || parts[1] == "" {
		return physicalDir, nil
	}
	
	// בדיקת סיומת הקובץ
	filePath := parts[1]
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext != "" && !sfm.allowedExtensions[ext] {
		return "", fmt.Errorf("סוג קובץ לא מורשה: %s", ext)
	}
	
	// וידוא שאין path traversal
	cleanedPath := filepath.Clean(filepath.Join(physicalDir, filepath.Clean(filePath)))
	if !strings.HasPrefix(cleanedPath, physicalDir) {
		return "", fmt.Errorf("ניסיון path traversal")
	}
	
	return cleanedPath, nil
}

// שירות קובץ
func (sfm *SafeFileManager) ServeFile(w http.ResponseWriter, r *http.Request) {
	// קבלת הנתיב מה-URL
	requestPath := r.URL.Path
	
	// תפיסת מקרה מיוחד עבור נתיב השורש
	if requestPath == "/" || requestPath == "" {
		http.Error(w, "נתיב הקובץ נדרש", http.StatusBadRequest)
		return
	}
	
	// הסרת "/files" מתחילת הנתיב אם קיים
	requestPath = strings.TrimPrefix(requestPath, "/files")
	requestPath = strings.TrimPrefix(requestPath, "/")
	
	// אימות ופתרון הנתיב
	physicalPath, err := sfm.ResolvePath(requestPath)
	if err != nil {
		log.Printf("שגיאת אימות נתיב: %v", err)
		http.Error(w, "נתיב לא חוקי", http.StatusBadRequest)
		return
	}
	
	// בדיקה אם הקובץ קיים
	fileInfo, err := os.Stat(physicalPath)
	if os.IsNotExist(err) {
		http.Error(w, "הקובץ לא נמצא", http.StatusNotFound)
		return
	} else if err != nil {
		log.Printf("שגיאת גישה לקובץ: %v", err)
		http.Error(w, "שגיאת מערכת", http.StatusInternalServerError)
		return
	}
	
	// אם זוהי תיקייה, דחה את הבקשה או הצג רשימה
	if fileInfo.IsDir() {
		http.Error(w, "לא ניתן להציג תיקיות", http.StatusForbidden)
		return
	}
	
	// פתיחת הקובץ
	file, err := os.Open(physicalPath)
	if err != nil {
		log.Printf("שגיאה בפתיחת הקובץ: %v", err)
		http.Error(w, "שגיאת גישה לקובץ", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	// זיהוי סוג MIME
	contentType := mime.TypeByExtension(filepath.Ext(physicalPath))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	
	// הגדרת כותרות HTTP
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "inline; filename="+filepath.Base(physicalPath))
	w.Header().Set("Cache-Control", "public, max-age=86400") // שמור במטמון למשך יום
	w.Header().Set("Last-Modified", fileInfo.ModTime().UTC().Format(http.TimeFormat))
	
	// שליחת התוכן
	http.ServeContent(w, r, filepath.Base(physicalPath), fileInfo.ModTime(), file)
}

// העלאת קובץ
func (sfm *SafeFileManager) HandleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "רק POST מורשה", http.StatusMethodNotAllowed)
		return
	}
	
	// הגבלת גודל הטופס ל-10MB
	r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "הקובץ גדול מדי או פורמט שגוי", http.StatusBadRequest)
		return
	}
	
	// קבלת הקובץ מהטופס
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "שגיאה בקבלת הקובץ", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// אימות סוג הקובץ
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if !sfm.allowedExtensions[ext] {
		http.Error(w, "סוג קובץ לא מורשה", http.StatusForbidden)
		return
	}
	
	// יצירת שם קובץ בטוח
	safeFilename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), sfm.sanitizeFilename(header.Filename))
	
	// קבלת תיקיית היעד מהטופס
	destDir := r.FormValue("directory")
	physicalDir, exists := sfm.virtualDirs[destDir]
	if !exists {
		http.Error(w, "תיקיית יעד לא חוקית", http.StatusBadRequest)
		return
	}
	
	// יצירת נתיב קובץ המטרה
	destPath := filepath.Join(physicalDir, safeFilename)
	
	// יצירת קובץ היעד
	outFile, err := os.Create(destPath)
	if err != nil {
		log.Printf("שגיאה ביצירת קובץ יעד: %v", err)
		http.Error(w, "שגיאת שרת פנימית", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()
	
	// העתקת התוכן
	_, err = io.Copy(outFile, file)
	if err != nil {
		log.Printf("שגיאה בכתיבת קובץ: %v", err)
		http.Error(w, "שגיאת שרת פנימית", http.StatusInternalServerError)
		return
	}
	
	// שליחת תשובה מוצלחת
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, \`{"success": true, "filename": "%s", "path": "%s/%s"}\`, 
		safeFilename, destDir, safeFilename)
}

// סניטציה של שם קובץ
func (sfm *SafeFileManager) sanitizeFilename(filename string) string {
	// לקיחת רק שם הבסיס
	filename = filepath.Base(filename)
	
	// החלפת תווים מסוכנים
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
	// יצירת מנהל הקבצים המאובטח
	fileManager := NewSafeFileManager("./storage")
	if err := fileManager.Init(); err != nil {
		log.Fatalf("שגיאה באתחול מנהל הקבצים: %v", err)
	}
	
	// הגדרת נתיבים
	http.HandleFunc("/files/", fileManager.ServeFile)
	http.HandleFunc("/upload", fileManager.HandleUpload)
	
	// הפעלת השרת
	log.Println("שרת מאזין בכתובת :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">כותרות HTTP מאובטחות ב-Go</h2>
                <p className="mb-4">
                  קביעת תצורה נכונה של כותרות HTTP חשובה להגנה על יישומי אינטרנט ב-Go.
                </p>
                
                <CodeExample
                  language="go"
                  title="יישום כותרות אבטחה"
                  code={`// מאובטח: הוספת כותרות HTTP אבטחה
package main

import (
	"net/http"
)

func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// הגדרת כותרות אבטחה
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer-when-downgrade")
		w.Header().Set("Feature-Policy", "camera 'none'; microphone 'none'")
		
		// עוגיות HTTPS בלבד
		w.Header().Set("Set-Cookie", "HttpOnly; Secure; SameSite=Strict")
		
		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	
	// רישום נתיבים
	mux.HandleFunc("/", homeHandler)
	
	// כריכה עם middleware אבטחה
	http.ListenAndServe(":8080", securityMiddleware(mux))
}`}
                />

                <CodeExample
                  language="go"
                  title="יישום מתקדם של middleware אבטחה"
                  code={`// מימוש מקיף של middleware אבטחה עם אפשרויות מתקדמות
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"strings"
	"time"
)

// אפשרויות לסביבת הפעלה
type Environment string
const (
	Development Environment = "development"
	Production  Environment = "production"
	Testing     Environment = "testing"
)

// אפשרויות קונפיגורציית האבטחה
type SecurityOptions struct {
	Environment Environment
	
	// כותרות אבטחה
	EnableCSP            bool
	EnableXSSProtection  bool
	EnableFrameOptions   bool
	EnableHSTS           bool
	
	// אפשרויות TLS
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
	
	// עוגיות
	CookiePrefix         string
	CookieDomain         string
	CookiePath           string
}

// ערכי ברירת מחדל לאבטחה
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

// מנהל האבטחה
type SecurityManager struct {
	options SecurityOptions
	rateLimiter *RateLimiter
}

// יצירת מנהל אבטחה
func NewSecurityManager(options SecurityOptions) *SecurityManager {
	// אתחול rate limiter אם הוא מופעל
	var limiter *RateLimiter
	if options.EnableRateLimit {
		limiter = NewRateLimiter(options.RequestsPerMinute)
	}
	
	return &SecurityManager{
		options: options,
		rateLimiter: limiter,
	}
}

// פונקציית middleware לאבטחה
func (sm *SecurityManager) SecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Rate Limiting
		if sm.options.EnableRateLimit {
			clientIP := r.RemoteAddr
			if !sm.rateLimiter.AllowRequest(clientIP) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "יותר מדי בקשות, נסה שוב מאוחר יותר", http.StatusTooManyRequests)
				return
			}
		}
		
		// הגדרת כותרות אבטחה
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
				
				// טיפול בבקשות preflight
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusOK)
					return
				}
			}
		}
		
		// תוסף מידע אבטחה להקשר
		ctx := context.WithValue(r.Context(), "security", map[string]interface{}{
			"environment": sm.options.Environment,
			"secure": r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		})
		
		// המשך לטיפול הבא
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// הגדרת כותרות אבטחה
func (sm *SecurityManager) setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	// כותרות אבטחה בסיסיות
	w.Header().Set("X-Content-Type-Options", "nosniff")
	
	// Content-Security-Policy
	if sm.options.EnableCSP {
		cspValue := "default-src 'self'; "
		
		// אפשרויות CSP נוספות לפי סביבה
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
	
	// HSTS - רק לחיבורי HTTPS
	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	if sm.options.EnableHSTS && isSecure && sm.options.Environment == Production {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	}
	
	// כותרות נוספות
	w.Header().Set("Referrer-Policy", "no-referrer-when-downgrade")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
}

// בדיקת האם המקור מורשה
func (sm *SecurityManager) isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}
	
	// אם אין רשימת מקורות מורשים, אל תאפשר CORS
	if len(sm.options.AllowedOrigins) == 0 {
		return false
	}
	
	// בדוק אם יש * בתוך רשימת המקורות (הרשאה לכולם)
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

// הגדרת עוגייה מאובטחת
func (sm *SecurityManager) SetSecureCookie(w http.ResponseWriter, name, value string, maxAge int) {
	isSecure := sm.options.Environment == Production
	
	// הוסף קידומת אבטחה אם צריך
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

// מנגנון הגבלת קצב בקשות
type RateLimiter struct {
	requestsPerMinute int
	clients           map[string]*ClientBucket
	cleanupInterval   time.Duration
	lastCleanup       time.Time
}

// דלי בקשות לקליינט
type ClientBucket struct {
	tokens    int
	lastRefill time.Time
}

// יצירת rate limiter חדש
func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	return &RateLimiter{
		requestsPerMinute: requestsPerMinute,
		clients:           make(map[string]*ClientBucket),
		cleanupInterval:   5 * time.Minute,
		lastCleanup:       time.Now(),
	}
}

// בדיקה האם לאפשר בקשה
func (rl *RateLimiter) AllowRequest(clientIP string) bool {
	// ניקוי תקופתי של לקוחות ישנים
	rl.performCleanupIfNeeded()
	
	// קבלת דלי הלקוח או יצירת חדש
	bucket, exists := rl.clients[clientIP]
	if !exists {
		bucket = &ClientBucket{
			tokens:     rl.requestsPerMinute,
			lastRefill: time.Now(),
		}
		rl.clients[clientIP] = bucket
	}
	
	// חישוב זמן עדכון הטוקנים האחרון
	now := time.Now()
	timePassed := now.Sub(bucket.lastRefill)
	
	// מילוי מחדש של הטוקנים לפי הזמן שעבר
	tokensToAdd := int(timePassed.Minutes() * float64(rl.requestsPerMinute))
	if tokensToAdd > 0 {
		bucket.tokens = min(bucket.tokens+tokensToAdd, rl.requestsPerMinute)
		bucket.lastRefill = now
	}
	
	// בדוק אם יש מספיק טוקנים
	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}
	
	return false
}

// פונקציית מינימום
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ניקוי לקוחות ישנים
func (rl *RateLimiter) performCleanupIfNeeded() {
	now := time.Now()
	if now.Sub(rl.lastCleanup) > rl.cleanupInterval {
		for ip, bucket := range rl.clients {
			// הסר לקוחות שלא היו פעילים למשך יותר מ-30 דקות
			if now.Sub(bucket.lastRefill) > 30*time.Minute {
				delete(rl.clients, ip)
			}
		}
		rl.lastCleanup = now
	}
}

// דוגמה לתוכנית עם אבטחה
func main() {
	// יצירת אפשרויות אבטחה
	options := DefaultSecurityOptions()
	options.AllowedOrigins = []string{"https://example.com", "https://api.example.com"}
	options.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE"}
	options.AllowedHeaders = []string{"Content-Type", "Authorization"}
	options.CookieDomain = "example.com"
	
	// תצורת TLS מאובטחת
	options.EnableTLS = true
	options.TLSCertFile = "cert.pem"
	options.TLSKeyFile = "key.pem"
	
	// יצירת מנהל אבטחה
	securityManager := NewSecurityManager(options)
	
	// יצירת נתב HTTP
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// דוגמה לשימוש בעוגייה מאובטחת
		securityManager.SetSecureCookie(w, "session", "abc123", 3600)
		w.Write([]byte("שלום עולם מאובטח!"))
	})
	
	// החלת middleware האבטחה
	secureHandler := securityManager.SecurityMiddleware(mux)
	
	// אתחול שרת ב-TLS אם מופעל
	if options.EnableTLS {
		// תצורת TLS מאובטחת
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
		
		// הגדרת שרת HTTP
		server := &http.Server{
			Addr:         ":8443",
			Handler:      secureHandler,
			TLSConfig:    tlsConfig,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
		
		log.Println("שרת מאובטח פועל בכתובת https://localhost:8443")
		log.Fatal(server.ListenAndServeTLS(options.TLSCertFile, options.TLSKeyFile))
		
	} else {
		// אירוח רגיל
		server := &http.Server{
			Addr:         ":8080",
			Handler:      secureHandler,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
		
		log.Println("שרת פועל בכתובת http://localhost:8080")
		log.Fatal(server.ListenAndServe())
	}
}`}
                />
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">בעיות אבטחה נפוצות ב-Golang</h3>
                  <ul className="space-y-2 pl-4 text-cybr-foreground/80">
                    <li>הזרקת פקודות (Command Injection)</li>
                    <li>הזרקת SQL</li>
                    <li>Path Traversal</li>
                    <li>דסריאליזציה לא מאובטחת</li>
                    <li>מצבי מירוץ (Race Conditions)</li>
                    <li>בעיות גישה מקבילית</li>
                    <li>תצורת TLS לא נכונה</li>
                    <li>שגיאות זליגת מידע</li>
                    <li>טיפול לא נאות בקבצי רגישים</li>
                    <li>ערבוב זיכרון משותף</li>
                    <li>זליגת מידע בשגיאות</li>
                    <li>חוסר אקראיות מספקת</li>
                    <li>אימות לא מספק של קלט משתמש</li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">כלי אבטחה ל-Golang</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/securego/gosec" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">gosec</a></li>
                    <li><a href="https://github.com/golang/lint" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">golint</a></li>
                    <li><a href="https://github.com/dominikh/go-tools" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">staticcheck</a></li>
                    <li><a href="https://github.com/sonatype-nexus-community/nancy" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">nancy (בודק תלויות)</a></li>
                    <li><a href="https://github.com/golang/vuln" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">govulncheck</a></li>
                    <li><a href="https://github.com/quasilyte/go-ruleguard" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">ruleguard</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">משאבי אבטחה ב-Go</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://blog.golang.org/go-security-release-process" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">תהליך שחרור אבטחה של Go</a></li>
                    <li><a href="https://golang.org/doc/security" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">מדיניות האבטחה של Go</a></li>
                    <li><a href="https://github.com/OWASP/Go-SCP" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Go Secure Coding Practices</a></li>
                    <li><a href="https://golang.org/pkg/crypto/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">חבילת הקריפטוגרפיה של Go</a></li>
                    <li><a href="https://pkg.go.dev/golang.org/x/crypto" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">הרחבות הקריפטוגרפיה של Go</a></li>
                  </ul>
                </div>

                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">ספריות אבטחה מומלצות</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/unrolled/secure" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">unrolled/secure</a></li>
                    <li><a href="https://github.com/gorilla/csrf" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">gorilla/csrf</a></li>
                    <li><a href="https://github.com/justinas/nosurf" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">justinas/nosurf</a></li>
                    <li><a href="https://github.com/golang-jwt/jwt" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">golang-jwt/jwt</a></li>
                    <li><a href="https://github.com/microcosm-cc/bluemonday" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">bluemonday (סינון HTML)</a></li>
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
