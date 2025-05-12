
import { Challenge } from './challenge-types';

export const pathTraversalChallenges: Challenge[] = [
  {
    id: 'path-traversal-1',
    title: 'Path Traversal in File Download',
    description: 'Compare these two Python functions that handle file downloads. Which one is secure against path traversal attacks?',
    difficulty: 'hard',
    category: 'Path Traversal',
    languages: ['Python'],
    type: 'comparison',
    vulnerabilityType: 'Path Traversal',
    secureCode: `import os
from flask import Flask, send_file, request, abort
import re

app = Flask(__name__)

@app.route('/download')
def download_file():
    filename = request.args.get('filename')
    
    if not filename or not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
        abort(400, "Invalid filename")
    
    file_path = os.path.join('safe_files_directory', filename)
    
    # Ensure the resolved path is within the intended directory
    safe_directory = os.path.abspath('safe_files_directory')
    requested_path = os.path.abspath(file_path)
    
    if not requested_path.startswith(safe_directory):
        abort(403, "Access denied")
    
    if not os.path.exists(file_path):
        abort(404, "File not found")
    
    return send_file(file_path)`,
    vulnerableCode: `import os
from flask import Flask, send_file, request

app = Flask(__name__)

@app.route('/download')
def download_file():
    filename = request.args.get('filename')
    
    if not filename:
        return "Filename is required", 400
    
    file_path = os.path.join('safe_files_directory', filename)
    
    if not os.path.exists(file_path):
        return "File not found", 404
    
    return send_file(file_path)`,
    answer: 'secure',
    explanation: "The secure version prevents path traversal by: 1) Validating the filename with a regex to ensure it only contains safe characters, 2) Converting both the intended directory and the requested path to absolute paths, and 3) Checking that the requested path starts with the safe directory path. The vulnerable version doesn't validate the filename, allowing attackers to use '../' sequences to traverse outside the intended directory."
  }
];
