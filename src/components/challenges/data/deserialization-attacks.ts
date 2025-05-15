
import { Challenge } from './challenge-types';

export const deserializationAttacksChallenges: Challenge[] = [
  {
    id: 'deserialization-attacks-1',
    title: 'PHP Unserialized Object Injection',
    description: 'This PHP code uses user-controlled data for object deserialization. What vulnerability does this introduce?',
    difficulty: 'hard',
    category: 'Insecure Deserialization',
    languages: ['PHP'],
    type: 'single',
    vulnerabilityType: 'PHP Object Injection',
    code: `<?php
class UserPreferences {
    public $theme;
    public $language;
    public $timezone;
    
    // When the object is destroyed
    function __destruct() {
        if(isset($this->theme)) {
            // Apply theme settings
            file_put_contents("themes/{$this->theme}.css", "/* Updated */", FILE_APPEND);
        }
    }
}

// User authentication code...

// Load user preferences from cookie
if(isset($_COOKIE['user_prefs'])) {
    // Unserialize user preferences
    $userPrefs = unserialize($_COOKIE['user_prefs']);
    
    // Use the preferences
    $theme = $userPrefs->theme;
    $language = $userPrefs->language;
    $timezone = $userPrefs->timezone;
}

// Display page with user preferences
?>`,
    answer: false,
    explanation: "This code is vulnerable to PHP Object Injection through insecure deserialization. It directly unserializes user-controlled data from a cookie without any validation. An attacker can craft a serialized UserPreferences object with a malicious 'theme' value that could lead to arbitrary file write via the __destruct() method. For example, they could set the theme to '../config' to modify configuration files. To fix this, either avoid using unserialize() on user input or implement a whitelist approach with allowed classes using PHP 7.0+'s second parameter: unserialize($data, ['allowed_classes' => ['UserPreferences']])."
  },
  {
    id: 'deserialization-attacks-2',
    title: 'Java Deserialization Vulnerability',
    description: 'Identify the security issues in this Java code that deserializes user data.',
    difficulty: 'hard',
    category: 'Insecure Deserialization',
    languages: ['Java'],
    type: 'multiple-choice',
    vulnerabilityType: 'Java Deserialization',
    code: `import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class UserProfileServlet extends HttpServlet {
    
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        
        // Get serialized user data from request
        String serializedData = request.getParameter("userData");
        
        if (serializedData != null) {
            try {
                // Decode from base64
                byte[] bytes = Base64.getDecoder().decode(serializedData);
                
                // Deserialize user data
                ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
                ObjectInputStream ois = new ObjectInputStream(bis);
                
                // Cast to UserProfile
                UserProfile profile = (UserProfile) ois.readObject();
                ois.close();
                
                // Use profile data
                String username = profile.getUsername();
                String email = profile.getEmail();
                
                // Return user data in response
                response.getWriter().println("Username: " + username);
                response.getWriter().println("Email: " + email);
                
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }
}`,
    options: [
      'The code uses Base64 encoding which is not secure',
      'The servlet doesn\'t validate input parameters',
      'Unrestricted deserialization of user-controlled data can lead to remote code execution',
      'The ObjectInputStream is not properly closed in the finally block'
    ],
    answer: 2,
    explanation: "The primary security issue is unrestricted deserialization of user-controlled data, which can lead to remote code execution. When Java deserializes an object, it can execute code in special methods like readObject(). If an attacker provides serialized data containing a malicious class with an overridden readObject() method, they could execute arbitrary code on the server. To mitigate this, use serialization filters (available in Java 9+), validate all serialized data, consider using safer formats like JSON, or implement a whitelist of allowed classes."
  }
];
