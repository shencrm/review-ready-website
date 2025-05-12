
import { Challenge } from './challenge-types';

export const xssChallenges: Challenge[] = [
  {
    id: 'xss-1',
    title: 'Cross-Site Scripting in React',
    description: 'Is this React component vulnerable to XSS attacks?',
    difficulty: 'medium',
    category: 'Cross-Site Scripting',
    languages: ['JavaScript', 'React'],
    type: 'single',
    vulnerabilityType: 'XSS',
    code: `import React from 'react';

function CommentDisplay({ comment }) {
  return (
    <div className="comment-box">
      <h3>User Comment:</h3>
      <div dangerouslySetInnerHTML={{ __html: comment }} />
    </div>
  );
}

export default CommentDisplay;`,
    answer: false,
    explanation: "This component is vulnerable to XSS attacks because it uses dangerouslySetInnerHTML to directly insert user-provided content (comment) into the DOM. If comment contains malicious JavaScript like '<script>alert(\\\"XSS\\\")</script>' or '<img src=\\\"x\\\" onerror=\\\"alert(1)\\'>', it will be executed in the browser. To fix this, either avoid dangerouslySetInnerHTML or sanitize the input using a library like DOMPurify."
  },
  {
    id: 'xss-2',
    title: 'XSS Prevention in JavaScript',
    description: 'Compare these two JavaScript functions for displaying user comments. Which implementation is secure against XSS?',
    difficulty: 'easy',
    category: 'Cross-Site Scripting',
    languages: ['JavaScript'],
    type: 'comparison',
    vulnerabilityType: 'XSS',
    secureCode: `function displayUserComment(comment) {
  // Create text node instead of using innerHTML
  const commentNode = document.createTextNode(comment);
  const commentDiv = document.createElement('div');
  commentDiv.className = 'user-comment';
  commentDiv.appendChild(commentNode);
  
  // Add to the DOM
  document.getElementById('comments-container').appendChild(commentDiv);
}`,
    vulnerableCode: `function displayUserComment(comment) {
  // Directly insert the comment HTML
  const commentHTML = '<div class="user-comment">' + comment + '</div>';
  
  // Add to the DOM
  document.getElementById('comments-container').innerHTML += commentHTML;
}`,
    answer: 'secure',
    explanation: "The secure version uses document.createTextNode() which automatically escapes any HTML or JavaScript in the comment, preventing XSS. The vulnerable version uses innerHTML which directly interprets and executes any HTML or JavaScript in the comment string, making it vulnerable to XSS attacks."
  }
];
