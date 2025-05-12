
import { Challenge } from './challenge-types';

export const insecureDeserializationChallenges: Challenge[] = [
  {
    id: 'insecure-deserialization-1',
    title: 'Insecure Deserialization in Java',
    description: 'Review this Java code that deserializes user data. Is it vulnerable to insecure deserialization attacks?',
    difficulty: 'hard',
    category: 'Insecure Deserialization',
    languages: ['Java'],
    type: 'single',
    vulnerabilityType: 'Insecure Deserialization',
    code: `import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserDataServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Get serialized data from request
            String serializedData = request.getParameter("userData");
            byte[] data = Base64.getDecoder().decode(serializedData);
            
            // Deserialize the object
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bais);
            UserData userData = (UserData) ois.readObject();
            ois.close();
            
            // Use the deserialized object
            response.getWriter().println("Hello, " + userData.getUsername());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// User data class
class UserData implements Serializable {
    private String username;
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
}`,
    answer: false,
    explanation: "This code is vulnerable to insecure deserialization attacks because it deserializes user-provided data without any validation or filtering. An attacker could craft a malicious serialized object that, when deserialized, could execute arbitrary code through gadget chains in the classpath. To fix this, avoid deserializing untrusted data, or use safer alternatives like JSON. If deserialization is necessary, implement validation filters using ObjectInputFilter (Java 9+) or libraries like SerialKiller."
  }
];
