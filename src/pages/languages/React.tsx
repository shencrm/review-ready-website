
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import { Link } from 'react-router-dom';
import { ArrowRight, Shield, Lock, FileCode, Code } from 'lucide-react';

const ReactPage = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">אבטחת React</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              שיטות קידוד מאובטחות ומניעת פגיעויות ביישומי React.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">XSS ביישומי React</h2>
                <p className="mb-4">
                  למרות שעיצוב React מגן מפני רוב פגיעויות XSS באמצעות מנגנון escape אוטומטי,
                  ישנן מספר דרכים בהן מפתחים יכולים בטעות ליצור פרצות אבטחה.
                </p>
                
                <CodeExample
                  language="jsx"
                  title="שימוש מסוכן ב-dangerouslySetInnerHTML"
                  code={`// פגיע: שימוש לא נכון ב-dangerouslySetInnerHTML
function UserProfile({ userProvidedHtml }) {
  return (
    <div className="profile-bio">
      <div dangerouslySetInnerHTML={{ __html: userProvidedHtml }} />
    </div>
  );
}

// אם userProvidedHtml מכיל תגיות script זדוניות, הן יופעלו`}
                />
                
                <CodeExample
                  language="jsx"
                  title="הצגת תוכן מאובטחת"
                  code={`// מאובטח: שימוש בספריית סניטציה
import DOMPurify from 'dompurify';

function UserProfile({ userProvidedHtml }) {
  const sanitizedHtml = DOMPurify.sanitize(userProvidedHtml);
  
  return (
    <div className="profile-bio">
      <div dangerouslySetInnerHTML={{ __html: sanitizedHtml }} />
    </div>
  );
}

// חלופה: להימנע לחלוטין מניתוח HTML
function SaferUserProfile({ userProvidedText }) {
  return (
    <div className="profile-bio">
      {userProvidedText}
    </div>
  );
}`}
                />

                <CodeExample
                  language="jsx"
                  title="דוגמה מתקדמת להגנה מ-XSS ב-React"
                  code={`// הגישה המקיפה ביותר - סניטציה מלאה עם הגבלת תגיות מותרות
import DOMPurify from 'dompurify';
import React, { useState, useEffect } from 'react';

function SecureContentRenderer({ content, allowedTags = ['b', 'i', 'em', 'strong', 'a', 'p', 'br'] }) {
  const [sanitizedContent, setSanitizedContent] = useState('');
  
  useEffect(() => {
    // הגדר את התצורה של DOMPurify להגבלת התגיות המותרות והתכונות
    DOMPurify.setConfig({
      ALLOWED_TAGS: allowedTags,
      ALLOWED_ATTR: ['href', 'target', 'rel', 'title', 'class'],
      ALLOW_DATA_ATTR: false,
      ADD_ATTR: ['target'], // הוסף target="_blank" לקישורים
      FORBID_TAGS: ['script', 'style', 'iframe', 'form', 'object', 'embed'],
      FORBID_ATTR: ['onerror', 'onload', 'onclick']
    });
    
    // נקה את התוכן
    const cleaned = DOMPurify.sanitize(content, {
      USE_PROFILES: { html: true }
    });
    
    // הוסף rel="noopener noreferrer" לכל הקישורים
    const parser = new DOMParser();
    const doc = parser.parseFromString(cleaned, 'text/html');
    
    const links = doc.querySelectorAll('a');
    links.forEach(link => {
      link.setAttribute('rel', 'noopener noreferrer');
      link.setAttribute('target', '_blank');
    });
    
    // המר בחזרה לסטרינג
    const safeContent = doc.body.innerHTML;
    setSanitizedContent(safeContent);
  }, [content, allowedTags]);
  
  return (
    <div className="secure-content">
      {sanitizedContent ? (
        <div dangerouslySetInnerHTML={{ __html: sanitizedContent }} />
      ) : (
        <p>טוען תוכן מאובטח...</p>
      )}
    </div>
  );
}

function UserContentExample() {
  // דוגמה לשימוש
  const userContent = \`
    <h2>הכותרת שלי</h2>
    <p>פסקה <strong>עם</strong> <em>עיצוב</em></p>
    <script>alert('XSS ניסיון');</script>
    <a href="https://example.com" onclick="alert('XSS')">קישור לדוגמה</a>
    <iframe src="https://malicious-site.com"></iframe>
    <div data-custom="exploit">תג מותר אך עם תכונה אסורה</div>
  \`;
  
  return (
    <div className="user-content-container">
      <h1>תוכן משתמש מאובטח</h1>
      <SecureContentRenderer 
        content={userContent}
        allowedTags={['h2', 'h3', 'p', 'strong', 'em', 'a', 'ul', 'ol', 'li']}
      />
      
      <div className="mt-4 p-3 bg-yellow-100 border border-yellow-300 rounded">
        <p>הערה: התוכן סונן והוסרו ממנו תגיות אסורות כמו script, iframe ותכונות אירועים.</p>
      </div>
    </div>
  );
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">פגיעויות מבוססות URL</h2>
                <p className="mb-4">
                  אפליקציות React לעתים קרובות משתמשות בפרמטרים של URL בשליטת המשתמש, מה שעלול להכניס סיכוני אבטחה.
                </p>
                
                <CodeExample
                  language="jsx"
                  title="טיפול לא מאובטח ב-URL"
                  code={`// פגיע: שימוש ב-URL שסופקו על-ידי המשתמש ללא אימות
function ExternalLink({ url, children }) {
  return (
    <a href={url}>
      {children}
    </a>
  );
}

// עלול לשמש כך: <ExternalLink url="javascript:alert('XSS')">לחץ עליי</ExternalLink>
// מה שיוצר קישור פרוטוקול JavaScript שמריץ קוד`}
                />
                
                <CodeExample
                  language="jsx"
                  title="טיפול מאובטח ב-URL"
                  code={`// מאובטח: אימות וסניטציה של URL
function ExternalLink({ url, children }) {
  // אימות URLs - אפשר רק http ו-https
  const isSafeUrl = /^https?:\\/\\//.test(url);
  
  // השתמש בברירת מחדל לכתובות לא בטוחות
  const safeUrl = isSafeUrl ? url : '#';
  
  return (
    <a 
      href={safeUrl} 
      target="_blank"
      rel="noopener noreferrer"
    >
      {children}
      {!isSafeUrl && <span> (כתובת לא חוקית)</span>}
    </a>
  );
}`}
                />

                <CodeExample
                  language="jsx"
                  title="ניהול מקיף יותר של URL"
                  code={`// פתרון מתקדם לאימות וסינון URL
import { useState, useEffect } from 'react';

// הוק מותאם לאימות בטיחות URL
function useSafeUrl(initialUrl) {
  const [url, setUrl] = useState('');
  const [isValid, setIsValid] = useState(false);
  const [error, setError] = useState('');
  
  useEffect(() => {
    if (!initialUrl) {
      setUrl('#');
      setIsValid(false);
      setError('URL לא סופק');
      return;
    }
    
    try {
      // נסה לפרסר את ה-URL
      const parsedUrl = new URL(initialUrl);
      
      // בדוק את הפרוטוקול
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        setUrl('#');
        setIsValid(false);
        setError(\`פרוטוקול לא מורשה: \${parsedUrl.protocol}\`);
        return;
      }
      
      // רשימה שחורה של דומיינים ידועים כזדוניים
      const blacklistedDomains = ['evil.com', 'malware.site', 'phishing.example'];
      if (blacklistedDomains.includes(parsedUrl.hostname)) {
        setUrl('#');
        setIsValid(false);
        setError('דומיין חשוד זוהה');
        return;
      }
      
      // בדיקות נוספות לפי הצורך (לדוגמה, אורך הכתובת)
      if (initialUrl.length > 2000) {
        setUrl('#');
        setIsValid(false);
        setError('URL ארוך מדי');
        return;
      }
      
      // URL בטוח
      setUrl(initialUrl);
      setIsValid(true);
      setError('');
    } catch (error) {
      // URL לא חוקי שלא ניתן לפרסר
      setUrl('#');
      setIsValid(false);
      setError('פורמט URL לא חוקי');
    }
  }, [initialUrl]);
  
  return { url, isValid, error };
}

// רכיב עטוף לקישורים חיצוניים בטוחים
function SafeExternalLink({ url, children, className = '' }) {
  const { url: safeUrl, isValid, error } = useSafeUrl(url);
  
  return (
    <div className="safe-link-wrapper">
      <a 
        href={safeUrl} 
        target={isValid ? "_blank" : "_self"}
        rel={isValid ? "noopener noreferrer" : undefined}
        className={\`\${className} \${!isValid ? 'cursor-not-allowed opacity-70' : ''}\`}
      >
        {children}
      </a>
      {!isValid && (
        <div className="text-red-500 text-xs mt-1" title={error}>
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <span className="ml-1">קישור לא בטוח</span>
        </div>
      )}
    </div>
  );
}

// דוגמה לשימוש
function LinkDemo() {
  return (
    <div className="space-y-4">
      <h2>דוגמאות לקישורים:</h2>
      
      <div>
        <h3>קישור תקין:</h3>
        <SafeExternalLink url="https://example.com">אתר לדוגמה</SafeExternalLink>
      </div>
      
      <div>
        <h3>קישור עם פרוטוקול JavaScript (יחסם):</h3>
        <SafeExternalLink url="javascript:alert('XSS')">קישור JavaScript זדוני</SafeExternalLink>
      </div>
      
      <div>
        <h3>קישור לדומיין חשוד (יחסם):</h3>
        <SafeExternalLink url="https://evil.com">אתר חשוד</SafeExternalLink>
      </div>
      
      <div>
        <h3>קישור לא תקין (יחסם):</h3>
        <SafeExternalLink url="not-a-valid-url">קישור שגוי</SafeExternalLink>
      </div>
    </div>
  );
}`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">אבטחת Server-Side Rendering (SSR)</h2>
                <p className="mb-4">
                  רינדור צד שרת (SSR) ב-React מציג סוגיות אבטחה ספציפיות שאינן קיימות באפליקציות צד לקוח בלבד.
                </p>
                
                <CodeExample
                  language="jsx"
                  title="דליפת מידע ב-SSR"
                  code={`// פגיע: חשיפת מידע רגיש במצב התחלתי
function ServerComponent({ user }) {
  // השרת מרנדר זאת עם כל נתוני המשתמש
  return (
    <div>
      <script
        dangerouslySetInnerHTML={{
          __html: \`window.__INITIAL_STATE__ = \${JSON.stringify({
            currentUser: user // עשוי לכלול מידע רגיש!
          })}\`
        }}
      />
      <UserProfile user={user} />
    </div>
  );
}

// גם שדות פרטיים באובייקט user נחשפים ללקוח`}
                />
                
                <CodeExample
                  language="jsx"
                  title="טיפול מאובטח במצב התחלתי"
                  code={`// מאובטח: סינון מידע רגיש לפני חשיפה
function sanitizeUserData(user) {
  // כלול רק שדות בטוחים לחשיפת לקוח
  const { id, name, publicProfile } = user;
  return { id, name, publicProfile };
}

function ServerComponent({ user }) {
  const safeUserData = sanitizeUserData(user);
  
  return (
    <div>
      <script
        dangerouslySetInnerHTML={{
          __html: \`window.__INITIAL_STATE__ = \${JSON.stringify({
            currentUser: safeUserData
          })}\`
        }}
      />
      <UserProfile user={safeUserData} />
    </div>
  );
}`}
                />

                <CodeExample
                  language="jsx"
                  title="גישה מתקדמת לאבטחת SSR"
                  code={`// גישה מקיפה לאבטחת SSR ב-Next.js
import { useEffect } from 'react';
import { GetServerSideProps } from 'next';
import { serialize } from 'cookie';

// פונקציית סניטציה מקיפה
function sanitizeDataForClient(data) {
  // פונקציה רקורסיבית לסינון מידע רגיש מכל מבנה נתונים
  function sanitizeObject(obj) {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }
    
    // טיפול במערכים
    if (Array.isArray(obj)) {
      return obj.map(item => sanitizeObject(item));
    }
    
    // טיפול באובייקטים
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      // דלג על שדות רגישים
      if (['password', 'token', 'secret', 'apiKey', 'ssn', 'creditCard'].includes(key)) {
        continue;
      }
      
      // אם זה אובייקט, הפעל סניטציה רקורסיבית
      sanitized[key] = sanitizeObject(value);
    }
    
    return sanitized;
  }
  
  return sanitizeObject(data);
}

// הטמעת מצב התחלתי מאובטח
function SafeStateHydration({ pageProps }) {
  return (
    <>
      {/* העבר נתונים מאובטחים למצב התחלתי */}
      <script
        id="__NEXT_DATA_SANITIZED__"
        type="application/json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            props: sanitizeDataForClient(pageProps),
          })
        }}
      />
    </>
  );
}

// דוגמה לדף Next.js עם אבטחת SSR
function UserDashboard({ user, privateData, publicData }) {
  // במקום לסמוך על נתוני שרת, נעשה בקשת API נוספת למידע רגיש לאחר האימות בצד לקוח
  useEffect(() => {
    // פעולה זו תתבצע רק בצד לקוח לאחר הרינדור הראשוני
    const fetchSensitiveData = async () => {
      if (user && user.isAuthenticated) {
        try {
          const response = await fetch('/api/user/sensitive-data', {
            credentials: 'include' // שלח עוגיות
          });
          if (response.ok) {
            const sensitiveData = await response.json();
            // עדכן את המצב עם המידע הרגיש
            // משתמש רק ב-Client Side ולא מועבר ב-SSR
          }
        } catch (error) {
          console.error('שגיאה בטעינת מידע רגיש:', error);
        }
      }
    };
    
    fetchSensitiveData();
  }, [user]);

  return (
    <div>
      <SafeStateHydration pageProps={{ user, publicData }} />
      <h1>לוח המחוונים של {user.name}</h1>
      <div className="public-data">
        {/* הצג מידע ציבורי שהגיע מ-SSR */}
        <PublicProfile data={publicData} />
      </div>
      
      {/* רכיבים רגישים יוצגו רק בצד הלקוח לאחר אימות נוסף */}
      <ClientSideSecureComponent userId={user.id} />
    </div>
  );
}

// דוגמה לGetServerSideProps עם אבטחה
export const getServerSideProps: GetServerSideProps = async (context) => {
  // אימות המשתמש עם עוגיות מאובטחות HttpOnly
  const authCookie = context.req.cookies.authToken;
  
  // אם אין אימות, הפנה לדף הכניסה
  if (!authCookie) {
    return {
      redirect: {
        destination: '/login',
        permanent: false,
      }
    };
  }
  
  try {
    // אמת ואחזר נתוני משתמש בצד השרת
    const user = await validateUserSession(authCookie);
    
    // הגדר עוגיית אימות חדשה עם חיי מדף קצרים
    context.res.setHeader('Set-Cookie', [
      serialize('authToken', refreshedToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 3600, // שעה אחת
        path: '/',
      })
    ]);
    
    // אחזר מידע ציבורי ופרטי
    const publicData = await fetchPublicUserData(user.id);
    const privateData = await fetchPrivateUserData(user.id);
    
    // החזר נתונים מסוננים לאחר הסינטזיה
    return {
      props: {
        user: sanitizeDataForClient(user),
        publicData,
        // לא מחזיר privateData בכוונה - יאוחזר בצד הלקוח עם API call
      }
    };
  } catch (error) {
    console.error('שגיאת SSR:', error);
    
    // בעת שגיאת אימות, הסר את העוגייה ושלח ללוגין
    context.res.setHeader('Set-Cookie', [
      serialize('authToken', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        expires: new Date(0),
        path: '/',
      })
    ]);
    
    return {
      redirect: {
        destination: '/login?error=session_expired',
        permanent: false,
      }
    };
  }
};

export default UserDashboard;`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">אבטחת ניהול מצב ב-React</h2>
                <p className="mb-4">
                  מלכודות נפוצות בניהול מצב באפליקציות React שעלולות להוביל לפגיעויות אבטחה.
                </p>
                
                <CodeExample
                  language="jsx"
                  title="אחסון לא מאובטח של מידע רגיש"
                  code={`// פגיע: אחסון מידע רגיש ב-localStorage
function LoginForm() {
  const handleLogin = async (credentials) => {
    const response = await api.login(credentials);
    
    // אל תאחסן מידע רגיש ב-localStorage
    localStorage.setItem('authToken', response.token);
    localStorage.setItem('userDetails', JSON.stringify(response.user));
  };
  
  // שאר הרכיב...
}

// localStorage חשוף להתקפות XSS - כל סקריפט יכול לגשת אליו`}
                />
                
                <CodeExample
                  language="jsx"
                  title="מצב אימות מאובטח"
                  code={`// מאובטח: שימוש במצב זיכרון ובעוגיות HttpOnly
function LoginForm() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [user, setUser] = useState(null);
  
  const handleLogin = async (credentials) => {
    // הגדרת עוגיות HttpOnly, Secure נעשית ע"י הבקאנד
    const response = await api.login(credentials);
    
    // אחסן רק מידע לא רגיש במצב
    setIsLoggedIn(true);
    setUser({
      id: response.user.id,
      name: response.user.name,
      role: response.user.role
    });
    
    // פרטי אימות רגישים נשארים בעוגיות HttpOnly
    // מנוהלים על-ידי הדפדפן, לא נגישים ל-JavaScript
  };
  
  // שאר הרכיב...
}`}
                />

                <CodeExample
                  language="jsx"
                  title="יישום שלם של אבטחת מצב עם React Context API"
                  code={`// auth-context.js - יישום מקיף של אבטחת אימות ב-React
import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import jwtDecode from 'jwt-decode';

// יצירת הקונטקסט
const AuthContext = createContext(null);

// הוק להשתמש בקונטקסט האימות
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth חייב לשמש בתוך AuthProvider');
  }
  return context;
}

// ספק האימות
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // בדוק את מצב האימות כשהאפליקציה נטענת
  const checkAuthStatus = useCallback(async () => {
    try {
      setLoading(true);
      
      // בצע קריאת API לבדיקת תוקף האימות בהתבסס על עוגיות HttpOnly
      // העוגיות נשלחות באופן אוטומטי ב-credentials: 'include'
      const response = await fetch('/api/auth/verify', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new Error('פג תוקף הסשן');
      }
      
      const data = await response.json();
      
      // אחסן רק את המידע הלא-רגיש במצב
      setUser({
        id: data.id,
        name: data.name,
        email: data.email,
        role: data.role,
        permissions: data.permissions
      });
      
      setError(null);
      
    } catch (err) {
      setUser(null);
      setError('לא מחובר');
      console.error('שגיאת אימות:', err);
    } finally {
      setLoading(false);
    }
  }, []);
  
  // בדוק מצב אימות כשהרכיב נטען
  useEffect(() => {
    checkAuthStatus();
    
    // אופציונלי: רענון האימות בפרקי זמן קבועים
    const refreshInterval = setInterval(() => {
      if (user) { // רענן רק אם משתמש מחובר
        checkAuthStatus();
      }
    }, 10 * 60 * 1000); // כל 10 דקות
    
    return () => clearInterval(refreshInterval);
  }, [checkAuthStatus, user]);
  
  // פונקציית התחברות
  const login = async (credentials) => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'include', // חיוני לקבלת עוגיות HttpOnly
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(credentials)
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'שגיאת התחברות');
      }
      
      const data = await response.json();
      
      // אחסן רק מידע לא-רגיש במצב
      setUser({
        id: data.user.id,
        name: data.user.name,
        email: data.user.email,
        role: data.user.role,
        permissions: data.user.permissions
      });
      
      return true;
    } catch (err) {
      setError(err.message);
      return false;
    } finally {
      setLoading(false);
    }
  };
  
  // פונקציית התנתקות
  const logout = async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        }
      });
    } catch (err) {
      console.error('שגיאת התנתקות:', err);
    } finally {
      // גם אם הקריאה לשרת נכשלת, עדכן את המצב המקומי
      setUser(null);
    }
  };
  
  // בדוק אם למשתמש יש הרשאה מסוימת
  const hasPermission = (permission) => {
    if (!user || !user.permissions) return false;
    return user.permissions.includes(permission);
  };
  
  // בדוק אם למשתמש יש תפקיד מסוים
  const hasRole = (role) => {
    if (!user) return false;
    return user.role === role;
  };
  
  // הערך המסופק לצרכני הקונטקסט
  const contextValue = {
    user,
    isAuthenticated: !!user,
    loading,
    error,
    login,
    logout,
    checkAuthStatus,
    hasPermission,
    hasRole
  };
  
  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
}

// רכיב מאובטח שדורש אימות
export function ProtectedRoute({ children, requiredPermissions = [], requiredRoles = [] }) {
  const { isAuthenticated, user, hasPermission, hasRole, loading } = useAuth();
  
  if (loading) {
    return <div>טוען...</div>;
  }
  
  // בדוק אם המשתמש מחובר
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  
  // בדוק הרשאות אם צוינו
  if (requiredPermissions.length > 0) {
    const hasAllPermissions = requiredPermissions.every(perm => hasPermission(perm));
    if (!hasAllPermissions) {
      return <AccessDenied message="אין לך את ההרשאות הנדרשות לצפייה בעמוד זה" />;
    }
  }
  
  // בדוק תפקידים אם צוינו
  if (requiredRoles.length > 0) {
    const hasRequiredRole = requiredRoles.some(role => hasRole(role));
    if (!hasRequiredRole) {
      return <AccessDenied message="דרוש תפקיד גבוה יותר כדי לגשת לעמוד זה" />;
    }
  }
  
  return <>{children}</>;
}

// דוגמה לדף התחברות
function LoginPage() {
  const { login, error, isAuthenticated } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  
  const from = location.state?.from || '/dashboard';
  
  useEffect(() => {
    if (isAuthenticated) {
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, navigate, from]);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    const success = await login({ email, password });
    if (success) {
      navigate(from, { replace: true });
    }
  };
  
  return (
    <div className="login-page">
      <h1>התחברות</h1>
      <form onSubmit={handleSubmit}>
        {error && <div className="error-message">{error}</div>}
        <div>
          <label htmlFor="email">אימייל:</label>
          <input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        <div>
          <label htmlFor="password">סיסמה:</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <button type="submit">התחבר</button>
      </form>
    </div>
  );
}

// שימוש במערכת האימות באפליקציה
function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/dashboard" element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        } />
        <Route path="/admin" element={
          <ProtectedRoute requiredRoles={['admin']}>
            <AdminPanel />
          </ProtectedRoute>
        } />
        <Route path="/reports" element={
          <ProtectedRoute requiredPermissions={['view:reports']}>
            <ReportsPage />
          </ProtectedRoute>
        } />
      </Routes>
    </AuthProvider>
  );
}`}
                />
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">סוגיות אבטחה ב-React</h3>
                  <ul className="space-y-2 pl-4 text-cybr-foreground/80">
                    <li>שימוש לא נכון ב-dangerouslySetInnerHTML</li>
                    <li>URL לא מאומתים בקישורים</li>
                    <li>חשיפת מידע רגיש ב-SSR</li>
                    <li>ניהול מצב לא מאובטח</li>
                    <li>אימות קלט לא מספק</li>
                    <li>הכללת תלויות לא בטוחות</li>
                    <li>זיוף בקשות צולבות (CSRF)</li>
                    <li>חולשת וקטור DOM</li>
                    <li>דליפת מידע רגיש</li>
                    <li>היעדר בקרת גישה בקומפוננטות</li>
                    <li>ניהול אסימונים (טוקנים) לא מאובטח</li>
                    <li>רכיבים צד שלישי לא בטוחים</li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">כלי אבטחה ל-React</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/cure53/DOMPurify" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">DOMPurify</a></li>
                    <li><a href="https://github.com/snyk/snyk" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Snyk</a></li>
                    <li><a href="https://reactjs.org/docs/dom-elements.html" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">React DOM Elements</a></li>
                    <li><a href="https://eslint.org/docs/latest/rules/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">ESLint Rules</a></li>
                    <li><a href="https://www.npmjs.com/package/js-xss" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">js-xss</a></li>
                    <li><a href="https://www.npmjs.com/package/serialize-javascript" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">serialize-javascript</a></li>
                    <li><a href="https://www.npmjs.com/package/@hapi/joi" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">joi (אימות)</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">משאבי אבטחת React</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://reactjs.org/docs/security.html" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">React Security Docs</a></li>
                    <li><a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Top 10</a></li>
                    <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/React_Security_Cheat_Sheet.html" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP React Cheatsheet</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">טכנולוגיות קשורות</h3>
                  <div className="space-y-3">
                    <Link to="/languages/javascript" className="block text-cybr-primary hover:underline">אבטחת JavaScript</Link>
                    <Link to="/languages/nodejs" className="block text-cybr-primary hover:underline">אבטחת Node.js</Link>
                  </div>
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

export default ReactPage;
