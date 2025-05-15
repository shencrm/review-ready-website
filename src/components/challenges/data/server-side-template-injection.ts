
import { Challenge } from './challenge-types';

export const serverSideTemplateInjectionChallenges: Challenge[] = [
  {
    id: 'ssti-1',
    title: 'Server-Side Template Injection in Python',
    description: 'This Flask application uses Jinja2 templates. Identify the security vulnerability and how it could be exploited.',
    difficulty: 'medium',
    category: 'Injection Flaws',
    languages: ['Python'],
    type: 'single',
    vulnerabilityType: 'SSTI',
    code: `from flask import Flask, request, render_template_string
from flask_login import login_required, current_user

app = Flask(__name__)

@app.route('/dashboard')
@login_required
def dashboard():
    username = current_user.username
    template = '''
    <div class="header">
        <h1>Welcome, %s!</h1>
    </div>
    <div class="content">
        <p>Your personal dashboard</p>
    </div>
    ''' % username
    
    return render_template_string(template)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    template = '''
    <div class="search-results">
        <h2>Search Results for: %s</h2>
        <div id="results">
            <!-- Results will be loaded here -->
        </div>
    </div>
    ''' % query
    
    return render_template_string(template)`,
    answer: false,
    explanation: "This code is vulnerable to Server-Side Template Injection (SSTI) in the search route. It directly incorporates user input (query parameter 'q') into a template string without sanitization, then passes it to render_template_string(). An attacker can inject Jinja2 template expressions like {{ config.items() }} or {{ ''.__class__.__mro__[1].__subclasses__() }} to leak sensitive information or even execute arbitrary Python code. The dashboard route is safer as it uses authenticated user data, though best practice would be to never incorporate dynamic data directly into template strings. Instead, pass variables separately: render_template_string('<h2>Results for: {{ query }}</h2>', query=query)."
  }
];
