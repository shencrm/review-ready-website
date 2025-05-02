
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CodeExample from '@/components/CodeExample';
import { Link } from 'react-router-dom';
import { ArrowRight, Shield, Lock, Terminal, FileCode } from 'lucide-react';

const NodeJs = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">אבטחת Node.js</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              הבנה והפחתת פגיעויות אבטחה באפליקציות Node.js.
            </p>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section>
                <h2 className="text-2xl font-bold mb-4">הזרקת פקודות (Command Injection)</h2>
                <p className="mb-4">
                  פגיעויות הזרקת פקודות מתרחשות כאשר אפליקציה מעבירה נתונים לא מאובטחים מהמשתמש למעטפת המערכת.
                  ב-Node.js, זה קורה בדרך כלל בשימוש בפונקציות כמו child_process.exec() ללא חיטוי נאות.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="פגיעות הזרקת פקודות"
                  code={`// פגיע: שימוש בקלט משתמש ישירות בהרצת פקודה
const { exec } = require('child_process');

app.get('/check-domain', (req, res) => {
  const domain = req.query.domain;
  // המשתמש יכול להזריק פקודות באמצעות תווים כמו ; | && 
  exec('ping -c 1 ' + domain, (error, stdout, stderr) => {
    res.send(stdout);
  });
});

// קלט התוקף: "google.com && rm -rf /" יכול למחוק קבצים`}
                />
                
                <CodeExample
                  language="javascript"
                  title="הרצת פקודה מאובטחת"
                  code={`// מאובטח: שימוש ב-execFile עם ארגומנטים כמערך
const { execFile } = require('child_process');

app.get('/check-domain', (req, res) => {
  const domain = req.query.domain;
  
  // אימות קלט תחילה (דוגמה פשוטה)
  if (!domain.match(/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\\.[a-zA-Z]{2,})+$/)) {
    return res.status(400).send('דומיין לא חוקי');
  }
  
  // execFile לא מפעיל מעטפת ומקבל ארגומנטים כמערך
  execFile('ping', ['-c', '1', domain], (error, stdout, stderr) => {
    res.send(stdout);
  });
});`}
                />

                <CodeExample
                  language="javascript"
                  title="דוגמה נוספת להזרקת פקודות עם חיטוי מתקדם"
                  code={`// פתרון מתקדם יותר עם ספריית validator
const { exec } = require('child_process');
const validator = require('validator');

app.get('/dns-lookup', (req, res) => {
  let domain = req.query.domain;
  
  // וידוא שהערך הוא דומיין תקף
  if (!validator.isFQDN(domain)) {
    return res.status(400).json({ error: 'דומיין לא חוקי סופק' });
  }
  
  // בנייה מאובטחת של פקודה עם הארגומנט המאומת
  const command = 'nslookup';
  const args = [domain];
  
  // שימוש בspawn במקום exec לשליטה טובה יותר
  const { spawn } = require('child_process');
  const process = spawn(command, args);
  
  let output = '';
  let errorOutput = '';
  
  process.stdout.on('data', (data) => {
    output += data.toString();
  });
  
  process.stderr.on('data', (data) => {
    errorOutput += data.toString();
  });
  
  process.on('close', (code) => {
    if (code !== 0) {
      return res.status(500).json({ error: 'הפקודה נכשלה', details: errorOutput });
    }
    res.json({ result: output });
  });
});`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">Path Traversal (טיול בנתיבים)</h2>
                <p className="mb-4">
                  פגיעויות path traversal מאפשרות לתוקפים לגשת לקבצים מחוץ לתיקיות המיועדות,
                  ועלולות לחשוף נתונים רגישים או קבצי תצורה.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="פגיעות Path Traversal"
                  code={`// פגיע: קריאת קבצים עם קלט משתמש לא מחוטא
const fs = require('fs');
const path = require('path');

app.get('/download-file', (req, res) => {
  const filename = req.query.filename;
  // פגיע ל-path traversal
  const filePath = path.join(PUBLIC_FOLDER, filename);
  
  fs.readFile(filePath, (err, data) => {
    if (err) {
      return res.status(404).send('הקובץ לא נמצא');
    }
    res.send(data);
  });
});

// קלט התוקף: "../../../etc/passwd" יכול לקרוא קבצים רגישים`}
                />
                
                <CodeExample
                  language="javascript"
                  title="גישה מאובטחת לקבצים"
                  code={`// מאובטח: שימוש ב-path.normalize ובדיקה ל-path traversal
const fs = require('fs');
const path = require('path');

app.get('/download-file', (req, res) => {
  const filename = req.query.filename;
  
  // נרמול הנתיב ובדיקה אם הוא מתחיל בתיקיית הציבור
  const publicFolder = path.resolve(PUBLIC_FOLDER);
  const requestedPath = path.normalize(path.join(publicFolder, filename));
  
  // בדיקה שהנתיב המבוקש נמצא בתוך תיקיית הציבור
  if (!requestedPath.startsWith(publicFolder)) {
    return res.status(403).send('הגישה נדחתה');
  }
  
  fs.readFile(requestedPath, (err, data) => {
    if (err) {
      return res.status(404).send('הקובץ לא נמצא');
    }
    res.send(data);
  });
});`}
                />

                <CodeExample
                  language="javascript"
                  title="פתרון מקיף לבעיית Path Traversal"
                  code={`// גישה מקיפה יותר עם אימות קלט נוסף
const fs = require('fs');
const path = require('path');
const sanitize = require('sanitize-filename');

app.get('/serve-file', (req, res) => {
  // קבל וחטא את שם הקובץ המבוקש - מנקה מתווים מסוכנים
  let requestedFileName = sanitize(req.query.filename || '');
  
  if (!requestedFileName || requestedFileName === '') {
    return res.status(400).send('שם קובץ לא חוקי');
  }
  
  // מגביל לסוגי קבצים מותרים בלבד
  const allowedExtensions = ['.txt', '.pdf', '.png', '.jpg', '.jpeg', '.html'];
  const fileExt = path.extname(requestedFileName).toLowerCase();
  
  if (!allowedExtensions.includes(fileExt)) {
    return res.status(403).send('סוג קובץ לא מורשה');
  }
  
  // בונה נתיב קובץ מאובטח
  const publicFolder = path.resolve('./public/files');
  const filePath = path.join(publicFolder, requestedFileName);
  const normalizedPath = path.normalize(filePath);
  
  // וידוא שהנתיב הסופי עדיין בתוך התיקייה המותרת
  if (!normalizedPath.startsWith(publicFolder)) {
    return res.status(403).send('גישה אסורה');
  }
  
  // בדיקה שהקובץ קיים
  fs.access(normalizedPath, fs.constants.F_OK, (err) => {
    if (err) {
      return res.status(404).send('קובץ לא נמצא');
    }
    
    // הגדרת סוג התוכן המתאים לפי סיומת הקובץ
    const mimeTypes = {
      '.txt': 'text/plain',
      '.pdf': 'application/pdf',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.html': 'text/html'
    };
    
    res.setHeader('Content-Type', mimeTypes[fileExt] || 'application/octet-stream');
    // משתמש בקריאת זרם במקום לקרוא את כל הקובץ לזיכרון
    fs.createReadStream(normalizedPath).pipe(res);
  });
});`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">כותרות אבטחה HTTP ותצורת HTTP</h2>
                <p className="mb-4">
                  קביעת תצורה נכונה של כותרות HTTP היא חיונית לאפליקציות אינטרנט Node.js כדי למנוע מגוון התקפות.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="יישום כותרות HTTP מאובטחות"
                  code={`// כותרות HTTP מאובטחות עם Helmet
const express = require('express');
const helmet = require('helmet');
const app = express();

// החלת כותרות אבטחה שונות
app.use(helmet());

// או קביעת תצורה של כותרות בנפרד
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", 'trusted-cdn.com'],
    styleSrc: ["'self'", "'unsafe-inline'", 'trusted-cdn.com'],
    imgSrc: ["'self'", 'data:', 'trusted-cdn.com'],
    connectSrc: ["'self'", 'api.trusted-domain.com'],
    fontSrc: ["'self'", 'trusted-cdn.com'],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
  }
}));

app.use(helmet.xssFilter());
app.use(helmet.noSniff());
app.use(helmet.ieNoOpen());
app.use(helmet.frameguard({ action: 'deny' }));`}
                />

                <CodeExample
                  language="javascript"
                  title="יישום מעמיק יותר של כותרות ואבטחת HTTP"
                  code={`// קונפיגורציה מקיפה יותר של אבטחת HTTP
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const app = express();

// הגדרות בסיסיות
app.disable('x-powered-by'); // הסרת כותרת חשיפת מידע

// שימוש ב-Helmet לכותרות אבטחה
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: [],
    }
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: 'same-origin' },
  dnsPrefetchControl: { allow: false },
  expectCt: { maxAge: 86400, enforce: true },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  referrerPolicy: { policy: 'no-referrer' },
  xssFilter: true
}));

// הגדרות CORS מגבילות
app.use(cors({
  origin: 'https://myapp.com', // רק מקור ספציפי
  methods: ['GET', 'POST'], // רק שיטות מסוימות
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  credentials: true,
  maxAge: 3600
}));

// הגבלת קצב בקשות להגנה מפני Brute Force ו-DDoS
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 דקות
  max: 100, // הגבל כל IP ל-100 בקשות בכל חלון
  standardHeaders: true,
  legacyHeaders: false,
  message: 'יותר מדי בקשות מ-IP זה, אנא נסה שוב מאוחר יותר'
});

// האטת בקשות במקום לחסום אותן לגמרי
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 50,
  delayMs: 500, // מוסיף 500ms עיכוב לכל בקשה אחרי 50 בקשות
});

// החל את המגבלות על נתיבי אימות רגישים
app.use('/login', limiter);
app.use('/register', limiter);
app.use('/api/', speedLimiter);

// הגדר עוגיות בטוחות
app.use(session({
  secret: 'super-secret-key',
  name: '__Secure-sessionId', // שם עוגיה מאובטח
  cookie: {
    secure: true, // דורש HTTPS
    httpOnly: true, // לא נגיש ע"י JavaScript
    domain: 'example.com',
    path: '/',
    maxAge: 60 * 60 * 1000, // שעה אחת
    sameSite: 'strict'
  },
  resave: false,
  saveUninitialized: false
}));

// הוספת נתיבים מאובטחים
app.get('/secure-data', (req, res) => {
  // הוסף כותרות נוספות ספציפיות לבקשה
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  
  // השב תוכן מאובטח
  res.json({ secureData: 'מידע מאובטח כאן' });
});;`}
                />
              </section>
              
              <section>
                <h2 className="text-2xl font-bold mb-4">ניהול תלויות</h2>
                <p className="mb-4">
                  אפליקציות Node.js לעתים קרובות כוללות תלויות רבות, שעלולות להכניס פגיעויות אבטחה.
                </p>
                
                <CodeExample
                  language="bash"
                  title="חיפוש ותיקון תלויות פגיעות"
                  code={`# בדוק אם יש פגיעויות בתלויות
npm audit

# תקן פגיעויות באופן אוטומטי כאשר אפשרי
npm audit fix

# דו"ח מפורט
npm audit --json

# עדכן חבילה ספציפית
npm update vulnerable-package

# הרץ בדיקת אבטחה באמצעות כלים של צד שלישי
npx snyk test`}
                />

                <CodeExample
                  language="javascript"
                  title="ניהול אבטחת תלויות בסביבת ייצור"
                  code={`// דוגמה לתסריט המבטיח אבטחת תלויות לפני הפריסה
// script: check-dependencies.js

const { execSync } = require('child_process');
const fs = require('fs');

try {
  // בדיקה עם npm audit
  console.log('בודק תלויות עם npm audit...');
  const auditResults = execSync('npm audit --json').toString();
  const auditData = JSON.parse(auditResults);
  
  // בדוק אם יש פגיעויות קריטיות או גבוהות
  const criticalVulns = Object.values(auditData.vulnerabilities || {})
    .filter(v => ['critical', 'high'].includes(v.severity));
  
  if (criticalVulns.length > 0) {
    console.error('נמצאו פגיעויות קריטיות או גבוהות:');
    criticalVulns.forEach(v => {
      console.error(\`- \${v.name}: \${v.severity} - \${v.title}\`);
    });
    
    // נסה לתקן באופן אוטומטי
    console.log('מנסה לתקן פגיעויות באופן אוטומטי...');
    execSync('npm audit fix');
    
    // בדוק שוב אם התיקונים פתרו את הבעיות
    const postFixResults = execSync('npm audit --json').toString();
    const postFixData = JSON.parse(postFixResults);
    
    const remainingCriticalVulns = Object.values(postFixData.vulnerabilities || {})
      .filter(v => ['critical', 'high'].includes(v.severity));
    
    if (remainingCriticalVulns.length > 0) {
      console.error('פגיעויות נשארו אחרי ניסיון תיקון אוטומטי');
      process.exit(1); // כישלון - יעצור תהליך CI/CD
    }
  }
  
  // בדיקת חבילות נטושות
  console.log('בודק חבילות נטושות...');
  const outdatedResults = execSync('npm outdated --json').toString();
  const outdatedData = JSON.parse(outdatedResults);
  
  // התראה על חבילות שלא עודכנו במשך זמן רב
  const abandonedPackages = Object.keys(outdatedData)
    .filter(pkg => {
      const current = outdatedData[pkg].current;
      const latest = outdatedData[pkg].latest;
      const versionDiff = parseInt(latest.split('.')[0]) - parseInt(current.split('.')[0]);
      return versionDiff >= 2; // שתי גרסאות עיקריות מאחורה או יותר
    });
  
  if (abandonedPackages.length > 0) {
    console.warn('חבילות עם פיגור עדכון משמעותי:');
    abandonedPackages.forEach(pkg => console.warn(\`- \${pkg}: \${outdatedData[pkg].current} (latest: \${outdatedData[pkg].latest})\`));
    console.warn('שקול עדכון או החלפת חבילות אלה');
  }
  
  // מידע נוסף על לייסנס
  console.log('בודק רישיונות חבילות...');
  const licenseData = execSync('license-checker --json').toString();
  const licenses = JSON.parse(licenseData);
  
  const restrictedLicenses = ['GPL', 'AGPL', 'LGPL']; // דוגמה לרישיונות שעשויים להיות מוגבלים
  const problematicPackages = Object.entries(licenses)
    .filter(([pkg, data]) => restrictedLicenses.some(l => data.licenses.includes(l)));
  
  if (problematicPackages.length > 0) {
    console.warn('חבילות עם רישיונות פוטנציאליים בעייתיים:');
    problematicPackages.forEach(([pkg, data]) => console.warn(\`- \${pkg}: \${data.licenses}\`));
  }
  
  console.log('בדיקת תלויות הושלמה בהצלחה');
  process.exit(0);

} catch (error) {
  console.error('שגיאה בבדיקת תלויות:', error);
  process.exit(1);
}`}
                />
              </section>

              <section>
                <h2 className="text-2xl font-bold mb-4">קריפטוגרפיה ב-Node.js</h2>
                <p className="mb-4">
                  יישום נכון של פונקציות קריפטוגרפיות הוא חיוני לאבטחת נתונים בNode.js.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="הצפנה לא מאובטחת"
                  code={`// פגיע: שימוש באלגוריתם הצפנה מיושן ומפתח חלש
const crypto = require('crypto');

function encryptData(data) {
  // שגיאה: אלגוריתם מיושן (DES), גודל מפתח קצר מדי, וקטור התחלה קבוע
  const algorithm = 'des';
  const key = 'short123'; // מפתח קצר מדי
  const iv = Buffer.alloc(8, 0); // וקטור התחלה צפוי
  
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// בעיות:
// 1. אלגוריתם DES נחשב לא בטוח
// 2. מפתח קצר מדי
// 3. IV קבוע ולא רנדומלי
// 4. אין אימות של הנתונים המוצפנים (אין MAC)`}
                />
                
                <CodeExample
                  language="javascript"
                  title="הצפנה מאובטחת"
                  code={`// מאובטח: הצפנה מודרנית עם אימות
const crypto = require('crypto');

// פונקציה להצפנה בטוחה עם AES-GCM (כולל אימות)
async function encryptData(plaintext, password) {
  // צור מפתח מאובטח מהסיסמה באמצעות הנפקת מפתח מסוג PBKDF2
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
  
  // צור וקטור התחלה רנדומלי
  const iv = crypto.randomBytes(12); // AES-GCM מומלץ 12 בתים
  
  // צור מצפין GCM (Galois/Counter Mode - כולל אימות)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  // הצפן את הנתונים
  let encrypted = cipher.update(plaintext, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  
  // קבל את תג האימות (Authentication Tag)
  const authTag = cipher.getAuthTag().toString('base64');
  
  // החזר את כל המידע הדרוש לפענוח
  return {
    encrypted,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    authTag
  };
}

// פונקציה לפענוח
async function decryptData(encData, password) {
  try {
    // קח את המידע המוצפן והמטא-נתונים
    const salt = Buffer.from(encData.salt, 'base64');
    const iv = Buffer.from(encData.iv, 'base64');
    const authTag = Buffer.from(encData.authTag, 'base64');
    const encryptedText = encData.encrypted;
    
    // שחזר את המפתח משיטת הגזירה
    const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
    
    // צור מפענח
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag); // הגדר את תג האימות
    
    // פענח
    let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    // אם יש שגיאה בפענוח, כנראה שהנתונים זויפו או נזק
    throw new Error('אימות ההצפנה נכשל: הנתונים שונו או המפתח שגוי');
  }
}

// שימוש בפונקציות
async function example() {
  const password = 'סיסמה-חזקה-מאוד-ארוכה-113542637!';
  const sensitiveData = 'מידע רגיש מאוד לאחסון';
  
  try {
    // הצפן את המידע
    const encrypted = await encryptData(sensitiveData, password);
    console.log('מידע מוצפן:', encrypted);
    
    // פענח את המידע
    const decrypted = await decryptData(encrypted, password);
    console.log('מידע מפוענח:', decrypted);
    
    // ניסיון פענוח עם סיסמה שגויה - צריך להיכשל
    try {
      await decryptData(encrypted, 'סיסמה-שגויה');
    } catch (error) {
      console.log('הפענוח נכשל כצפוי עם סיסמה שגויה:', error.message);
    }
    
    // ניסיון טמפור עם המידע המוצפן - צריך להיכשל
    try {
      const tamperedData = {...encrypted};
      tamperedData.encrypted = tamperedData.encrypted.replace('a', 'b');
      await decryptData(tamperedData, password);
    } catch (error) {
      console.log('הפענוח נכשל כצפוי עם מידע שטופל:', error.message);
    }
    
  } catch (error) {
    console.error('שגיאה:', error);
  }
}

example();`}
                />
              </section>

              <section>
                <h2 className="text-2xl font-bold mb-4">אבטחת גישה לבסיס נתונים בNode.js</h2>
                <p className="mb-4">
                  אבטחת חיבורי מסדי נתונים מפני התקפות הזרקה וטיפול נכון במידע רגיש.
                </p>
                
                <CodeExample
                  language="javascript"
                  title="התחברות לא מאובטחת למסד נתונים"
                  code={`// פגיע: אחסון פרטי התחברות בקוד ושימוש ישיר בשאילתות סטרינגים
const mysql = require('mysql');

// מזהי התחברות קשיחים בקוד
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'my-secret-pw',
  database: 'my_db'
});

// שימוש פגיע - הזרקת SQL
app.get('/user', (req, res) => {
  const userId = req.query.id;
  // פגיע: הכנסה ישירה של משתנה לשאילתה
  const query = 'SELECT * FROM users WHERE id = ' + userId;
  
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
});

// התוקף יכול לשלוח: ?id=1 OR 1=1 כדי להשיג את כל המשתמשים`}
                />
                
                <CodeExample
                  language="javascript"
                  title="התחברות מאובטחת וגישה לבסיס הנתונים"
                  code={`// מאובטח: שימוש משתנים סביבתיים, מאגר חיבורים, ושאילתות מפורמטות
const mysql = require('mysql2/promise');
require('dotenv').config();

// פרטי התחברות מאובטחים משתני סביבה
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    rejectUnauthorized: true // וודא שחיבור SSL מאובטח
  },
  connectionLimit: 10 // הגבלת מאגר חיבורים
};

// יצירת מאגר חיבורים במקום חיבור בודד
const pool = mysql.createPool(dbConfig);

// פונקציית עזר לביצוע שאילתות מאובטחות
async function query(sql, params) {
  try {
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.execute(sql, params);
      return rows;
    } finally {
      conn.release(); // תמיד שחרר את החיבור בחזרה למאגר
    }
  } catch (error) {
    console.error('שגיאת שאילתת מסד נתונים:', error);
    throw new Error('שגיאת מסד נתונים');
  }
}

// שימוש במערכים מפורמטים למניעת הזרקת SQL
app.get('/user', async (req, res) => {
  try {
    const userId = req.query.id;
    
    // בדוק שה-ID הוא מספר תקין
    if (!/^\\d+$/.test(userId)) {
      return res.status(400).json({ error: 'מזהה משתמש לא חוקי' });
    }
    
    // שימוש בשאילתות מפורמטות
    const users = await query(
      'SELECT id, username, email FROM users WHERE id = ?', 
      [userId]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ error: 'משתמש לא נמצא' });
    }
    
    res.json(users[0]);
  } catch (error) {
    console.error('שגיאה בקבלת משתמש:', error);
    res.status(500).json({ error: 'שגיאת שרת פנימית' });
  }
});

// סגירת המאגר בעת סגירת האפליקציה
process.on('SIGINT', () => {
  pool.end();
  process.exit();
});`}
                />

                <CodeExample
                  language="javascript"
                  title="אבטחת MongoDB עם Mongoose"
                  code={`// מאובטח: שימוש ב-Mongoose עם אימות קלט וסינון פלט
const mongoose = require('mongoose');
const express = require('express');
require('dotenv').config();

// התחברות מאובטחת עם משתני סביבה
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
  serverSelectionTimeoutMS: 5000,
  ssl: true,
  sslValidate: true,
  authSource: 'admin',
});

// הגדרת סכמה עם אימות
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: [3, 'שם משתמש חייב להיות לפחות 3 תווים'],
    maxlength: [50, 'שם משתמש לא יכול לעבור 50 תווים'],
    match: [/^[a-zA-Z0-9_-]+$/, 'שם משתמש יכול להכיל רק אותיות, ספרות, מקפים וקו תחתון'],
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\\S+@\\S+\\.\\S+$/, 'אנא הזן כתובת אימייל תקינה'],
  },
  password: {
    type: String,
    required: true,
    minlength: [8, 'סיסמה חייבת להיות לפחות 8 תווים'],
    // לעולם אל תחזיר סיסמאות בשאילתות
    select: false,
  },
  role: {
    type: String,
    enum: ['user', 'admin', 'editor'],
    default: 'user',
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// הוסף hooks לפני שמירה
userSchema.pre('save', async function(next) {
  // הצפן סיסמאות לפני שמירה
  if (this.isModified('password')) {
    try {
      const bcrypt = require('bcryptjs');
      this.password = await bcrypt.hash(this.password, 12);
    } catch (err) {
      return next(err);
    }
  }
  next();
});

// אל תחזיר שדות רגישים
userSchema.methods.toJSON = function() {
  const userObject = this.toObject();
  delete userObject.password;
  delete userObject.__v;
  return userObject;
};

// הגדר מודל
const User = mongoose.model('User', userSchema);

// שימוש מאובטח עם mongoose
const app = express();
app.use(express.json());

// נתיב חיפוש משתמשים
app.get('/api/users/search', async (req, res) => {
  try {
    // שים לב: אין הזרקת NoSQL כאן בגלל שאנחנו בונים שאילתה מובנית
    const { username, limit = 10, page = 1 } = req.query;
    
    // וודא שהגבול הוא מספר ובטווח הגיוני
    const safeLimit = Math.min(parseInt(limit) || 10, 50);
    const safePage = parseInt(page) || 1;
    const skip = (safePage - 1) * safeLimit;
    
    const query = {};
    if (username) {
      // חיפוש בטוח עם ביטוי רגולרי
      query.username = { $regex: new RegExp('^' + username.replace(/[-\\/\\\\^$*+?.()|[\\]{}]/g, '\\\\$&')), $options: 'i' };
    }
    
    // בצע את שאילתת הסינון, אבל הגבל את השדות המוחזרים
    const users = await User.find(query)
      .select('username email role createdAt')
      .limit(safeLimit)
      .skip(skip)
      .sort({ createdAt: -1 });
    
    const totalUsers = await User.countDocuments(query);
    
    res.json({
      users,
      pagination: {
        total: totalUsers,
        page: safePage,
        limit: safeLimit,
        pages: Math.ceil(totalUsers / safeLimit)
      }
    });
  } catch (err) {
    console.error('שגיאת חיפוש משתמש:', err);
    res.status(500).json({ error: 'אירעה שגיאה בעת חיפוש משתמשים' });
  }
});`}
                />
              </section>
            </div>
            
            <div className="lg:col-span-1">
              <div className="sticky top-24">
                <div className="card">
                  <h3 className="text-xl font-bold mb-4">בעיות אבטחה נפוצות ב-Node.js</h3>
                  <ul className="space-y-2 pl-4 text-cybr-foreground/80">
                    <li>הזרקת פקודות (Command Injection)</li>
                    <li>Path Traversal</li>
                    <li>חריגות שלא טופלו (Unhandled Exceptions)</li>
                    <li>תלויות לא מאובטחות (Insecure Dependencies)</li>
                    <li>זיופי בקשת שרת (SSRF)</li>
                    <li>טיפול שגוי בשגיאות (Improper Error Handling)</li>
                    <li>הזרקת NoSQL</li>
                    <li>בעיות הרשאות לקבצים</li>
                    <li>הצפנה חלשה או חסרה</li>
                    <li>פרטי התחברות בקוד קשיח</li>
                    <li>חולשות בניהול סשן</li>
                    <li>פונקציות דסריאליזציה לא מאובטחות</li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">חבילות אבטחה חיוניות ל-Node.js</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/helmetjs/helmet" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Helmet</a></li>
                    <li><a href="https://github.com/expressjs/csurf" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">csurf (CSRF Protection)</a></li>
                    <li><a href="https://github.com/hapijs/joi" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">joi (Input Validation)</a></li>
                    <li><a href="https://github.com/auth0/node-jsonwebtoken" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">jsonwebtoken (JWT)</a></li>
                    <li><a href="https://github.com/validatorjs/validator.js" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">validator.js (String Validation)</a></li>
                    <li><a href="https://github.com/bcrypt-nodejs/bcrypt.js" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">bcrypt.js (Password Hashing)</a></li>
                    <li><a href="https://github.com/OWASP/NodeGoat" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">NodeGoat (OWASP Learning Project)</a></li>
                  </ul>
                </div>
                
                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">טכנולוגיות קשורות</h3>
                  <div className="space-y-3">
                    <Link to="/languages/javascript" className="block text-cybr-primary hover:underline">אבטחת JavaScript</Link>
                    <Link to="/languages/react" className="block text-cybr-primary hover:underline">אבטחת React</Link>
                    <Link to="/languages/golang" className="block text-cybr-primary hover:underline">אבטחת Golang</Link>
                  </div>
                </div>

                <div className="card mt-6">
                  <h3 className="text-xl font-bold mb-4">כלי סריקת אבטחה ל-Node.js</h3>
                  <ul className="space-y-3 text-cybr-foreground/80">
                    <li><a href="https://github.com/nodesecurity/nsp" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Node Security Platform</a></li>
                    <li><a href="https://github.com/snyk/snyk" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Snyk</a></li>
                    <li><a href="https://github.com/jeremylong/DependencyCheck" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">OWASP Dependency Check</a></li>
                    <li><a href="https://github.com/RetireJS/retire.js" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">Retire.js</a></li>
                    <li><a href="https://github.com/ajinabraham/NodeJsScan" target="_blank" rel="noreferrer" className="text-cybr-primary hover:underline">NodeJsScan</a></li>
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

export default NodeJs;
