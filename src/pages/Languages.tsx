
import React from 'react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import { Link } from 'react-router-dom';

const Languages = () => {
  const languages = [
    {
      name: "JavaScript",
      description: "למד על XSS, זיהום פרוטוטייפ, תלויות לא מאובטחות ופגיעויות JavaScript נפוצות אחרות.",
      path: "/languages/javascript",
      icon: "JS"
    },
    {
      name: "Python",
      description: "גלה פגיעויות בקוד Python, החל מדסריאליזציה לא מאובטחת ועד סיכוני הזרקת פקודות.",
      path: "/languages/python",
      icon: "PY"
    },
    {
      name: "Java",
      description: "חקור פגמי אבטחה נפוצים ב-Java כולל אימות לא תקין, CSRF, ופגיעויות XXE.",
      path: "/languages/java",
      icon: "JV"
    },
    {
      name: "C#",
      description: "הבן סוגיות אבטחה ב-.NET כולל הזרקת LINQ, דסריאליזציה לא מאובטחת, ובעיות בקרת גישה.",
      path: "/languages/csharp",
      icon: "C#"
    },
    {
      name: "PHP",
      description: "למד על פגיעויות PHP טיפוסיות כמו הרצת קוד מרחוק, הכללת קבצים, ואבטחת סשן.",
      path: "/languages/php",
      icon: "PHP"
    },
    {
      name: "React",
      description: "הבן פגיעויות אבטחה ב-React, ניהול סטייט מאובטח, וסיכוני XSS ייחודיים לאפליקציות React.",
      path: "/languages/react",
      icon: "RE"
    },
    {
      name: "Node.js",
      description: "למד על אבטחת שרת צד, פגיעויות במודולים, והזרקת פקודות בסביבת Node.js.",
      path: "/languages/nodejs",
      icon: "ND"
    },
    {
      name: "Golang",
      description: "חקור אבטחה של יישומי Go, ניהול שגיאות, והגנה מפני סכנות אבטחה שכיחות בשפה מודרנית זו.",
      path: "/languages/golang",
      icon: "GO"
    }
  ];

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      
      <main className="flex-grow py-12">
        <div className="container mx-auto px-4">
          <div className="mb-12">
            <h1 className="text-4xl font-bold mb-6">מדריכי אבטחה ספציפיים לשפות תכנות</h1>
            <div className="h-1 w-24 bg-cybr-primary mb-6"></div>
            <p className="text-xl text-cybr-foreground/80">
              חקור פגיעויות אבטחה ושיטות עבודה מומלצות עבור שפות תכנות שונות.
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {languages.map((language, index) => (
              <Link key={index} to={language.path} className="block group">
                <div className="card h-full group-hover:-translate-y-1 transition-transform duration-300">
                  <div className="flex items-start">
                    <div className="w-12 h-12 bg-cybr-muted rounded-md flex items-center justify-center text-cybr-primary font-mono text-xl font-bold mr-4">
                      {language.icon}
                    </div>
                    <div className="flex-1">
                      <h2 className="text-2xl font-bold mb-2 group-hover:text-cybr-primary transition-colors">
                        {language.name}
                      </h2>
                      <p className="text-cybr-foreground/80">
                        {language.description}
                      </p>
                    </div>
                  </div>
                </div>
              </Link>
            ))}
          </div>
          
          <div className="mt-16">
            <h2 className="text-2xl font-bold mb-6">למה אבטחה ספציפית לשפה חשובה</h2>
            <div className="card">
              <p className="mb-4">
                לכל שפת תכנות יש את האתגרים והפגיעויות הייחודיים לה. הבנת הנושאים הספציפיים 
                לכל שפה היא קריטית לביצוע סקירות קוד מאובטח אפקטיביות.
              </p>
              
              <p className="mb-4">
                בעוד שעקרונות אבטחה כלליים חלים על כל השפות, פרטי היישום והמלכודות הנפוצות 
                משתנים משמעותית. לדוגמה:
              </p>
              
              <ul className="list-disc list-inside space-y-3 pl-4 text-cybr-foreground/80">
                <li>JavaScript מתמודדת עם אתגרים ייחודיים עם ירושה מבוססת פרוטוטייפ ואינטראקציות DOM בדפדפן</li>
                <li>Python עם טיפוסים דינמיים יכולה להוביל לבעיות אבטחה לא צפויות הקשורות לטיפוסים</li>
                <li>מבנה הקלאסים המורכב של Java ומנגנוני סריאליזציה מציגים וקטורי תקיפה ספציפיים</li>
                <li>ליישומי C# יש פגיעויות ספציפיות למסגרת ה-.NET</li>
                <li>PHP היתה היסטורית נוטה לפגיעויות הכללה וחולשות הזרקה</li>
                <li>React דורשת הבנה של סיכוני אבטחה ייחודיים ב-SPA וניהול מצב</li>
                <li>Node.js מחייבת תשומת לב מיוחדת לאבטחת צד שרת בסביבת JavaScript</li>
                <li>Golang, למרות שהיא מודרנית יחסית, יכולה עדיין להיות פגיעה אם לא מיישמים נכון</li>
              </ul>
              
              <p className="mt-4">
                על ידי הבנת הסוגיות הספציפיות לשפה, תוכל לבצע סקירות אבטחה ממוקדות ואפקטיביות יותר.
              </p>
            </div>
          </div>
          
          <div className="mt-16">
            <h2 className="text-2xl font-bold mb-6">עקרונות אבטחה חוצי-שפות</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="card">
                <h3 className="text-xl font-bold mb-3">אימות קלט</h3>
                <p className="text-cybr-foreground/80">
                  תמיד אמת, חטא וקודד קלט משתמש ללא קשר לשפה. לעולם אל תסמוך על נתונים חיצוניים.
                </p>
              </div>
              
              <div className="card">
                <h3 className="text-xl font-bold mb-3">אימות והרשאות</h3>
                <p className="text-cybr-foreground/80">
                  יישם אימות זהות חזק ובקרות גישה נאותות באמצעות שיטות עבודה מומלצות ספציפיות לשפה.
                </p>
              </div>
              
              <div className="card">
                <h3 className="text-xl font-bold mb-3">הגנת מידע</h3>
                <p className="text-cybr-foreground/80">
                  השתמש בהצפנה מתאימה, מנגנוני אחסון מאובטחים, וטיפול זהיר במידע רגיש.
                </p>
              </div>
            </div>
          </div>
        </div>
      </main>
      
      <Footer />
    </div>
  );
};

export default Languages;
