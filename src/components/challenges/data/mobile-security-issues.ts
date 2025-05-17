import { Challenge } from './challenge-types';

export const mobileSecurityIssuesChallenges: Challenge[] = [
  {
    id: 'mobile-sec-1',
    title: 'Android Data Storage',
    description: 'Review this Android code that stores sensitive user data. What security best practice is being violated?',
    difficulty: 'medium',
    category: 'Mobile Security',
    languages: ['Java', 'Android'],
    type: 'multiple-choice',
    vulnerabilityType: 'Insecure Data Storage',
    code: `import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import android.widget.EditText;
import android.widget.CheckBox;
import android.widget.Button;

public class LoginActivity extends AppCompatActivity {
    
    private EditText usernameField;
    private EditText passwordField;
    private CheckBox rememberMeCheckbox;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(Bundle savedInstanceState);
        setContentView(R.layout.activity_login);
        
        usernameField = findViewById(R.id.username);
        passwordField = findViewById(R.id.password);
        rememberMeCheckbox = findViewById(R.id.remember_me);
        Button loginButton = findViewById(R.id.login_button);
        
        // Load saved credentials if they exist
        loadSavedCredentials();
        
        loginButton.setOnClickListener(view -> {
            String username = usernameField.getText().toString();
            String password = passwordField.getText().toString();
            
            // Validate and process login
            if (validateCredentials(username, password)) {
                if (rememberMeCheckbox.isChecked()) {
                    // Save credentials for next login
                    saveCredentials(username, password);
                }
                // Proceed with login
                startHomeActivity();
            } else {
                showLoginError();
            }
        });
    }
    
    private void saveCredentials(String username, String password) {
        SharedPreferences prefs = getSharedPreferences("UserPrefs", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("username", username);
        editor.putString("password", password);
        editor.apply();
    }
    
    private void loadSavedCredentials() {
        SharedPreferences prefs = getSharedPreferences("UserPrefs", Context.MODE_PRIVATE);
        String savedUsername = prefs.getString("username", "");
        String savedPassword = prefs.getString("password", "");
        
        if (!savedUsername.isEmpty() && !savedPassword.isEmpty()) {
            usernameField.setText(savedUsername);
            passwordField.setText(savedPassword);
            rememberMeCheckbox.setChecked(true);
        }
    }
    
    // Other methods...
}`,
    options: [
      'Storing user credentials in SharedPreferences as plaintext',
      'Not using HTTPS for network communication',
      'Missing certificate pinning',
      'Using a vulnerable third-party library'
    ],
    answer: 0,
    explanation: "The code violates a critical security best practice by storing sensitive user credentials (username and password) as plaintext in SharedPreferences. While SharedPreferences is a common way to store user preferences in Android, it's not designed for storing sensitive information like passwords. Though MODE_PRIVATE is used (which is good), the data is still stored unencrypted on the device and could be accessed if the device is rooted, compromised via malware, or if the app's data is backed up. Instead, sensitive data should be stored using Android's security features like the EncryptedSharedPreferences, Android Keystore System, or hardware-backed security features. Additionally, implementing a 'Remember Me' feature should store an authentication token rather than actual credentials."
  },
  {
    id: 'mobile-sec-2',
    title: 'iOS App Transport Security',
    description: 'Review this iOS Info.plist configuration. What security issue can you identify?',
    difficulty: 'medium',
    category: 'Mobile Security',
    languages: ['XML', 'iOS'],
    type: 'single',
    vulnerabilityType: 'Insecure Network Communication',
    code: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>$(EXECUTABLE_NAME)</string>
    <key>CFBundleIdentifier</key>
    <string>$(PRODUCT_BUNDLE_IDENTIFIER)</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>$(PRODUCT_NAME)</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSRequiresIPhoneOS</key>
    <true/>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
    <key>UILaunchStoryboardName</key>
    <string>LaunchScreen</string>
    <key>UIMainStoryboardFile</key>
    <string>Main</string>
    <key>UIRequiredDeviceCapabilities</key>
    <array>
        <string>armv7</string>
    </array>
    <key>UISupportedInterfaceOrientations</key>
    <array>
        <string>UIInterfaceOrientationPortrait</string>
    </array>
</dict>
</plist>`,
    answer: false,
    explanation: "This iOS Info.plist configuration has a significant security issue: it disables App Transport Security (ATS) by setting 'NSAllowsArbitraryLoads' to true. ATS is an important iOS security feature that enforces secure connections by requiring apps to use HTTPS with strong TLS settings. By disabling it completely, the app allows all HTTP connections without encryption, making user data vulnerable to interception, eavesdropping, and man-in-the-middle attacks. While there might be legitimate cases where exceptions are needed (like connecting to legacy APIs), a secure approach would be to use targeted exceptions with 'NSExceptionDomains' for specific domains rather than disabling ATS entirely. Apple's App Store review process scrutinizes apps that disable ATS and requires justification for doing so."
  }
];
