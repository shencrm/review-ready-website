
import { Challenge } from './challenge-types';

export const mobileSecurityChallenges: Challenge[] = [
  {
    id: 'mobile-security-1',
    title: 'Data Storage in React Native',
    description: 'Compare these two React Native code snippets for storing sensitive data. Which one is secure?',
    difficulty: 'medium',
    category: 'Mobile Security',
    languages: ['JavaScript', 'React Native'],
    type: 'comparison',
    vulnerabilityType: 'Insecure Data Storage',
    secureCode: `import React, { useState } from 'react';
import { View, Button, TextInput, Alert } from 'react-native';
import * as SecureStore from 'expo-secure-store';

export default function CreditCardScreen() {
  const [cardNumber, setCardNumber] = useState('');
  const [cvv, setCvv] = useState('');

  const saveCardDetails = async () => {
    try {
      // Validate input (basic validation)
      if (cardNumber.length !== 16 || cvv.length !== 3) {
        Alert.alert('Validation Error', 'Please enter valid card details');
        return;
      }
      
      // Store sensitive data in secure storage
      await SecureStore.setItemAsync(
        'user_payment_info',
        JSON.stringify({
          cardNumber: cardNumber,
          cvv: cvv,
          timestamp: new Date().toISOString()
        }),
        {
          keychainAccessible: SecureStore.WHEN_UNLOCKED
        }
      );
      
      Alert.alert('Success', 'Card details saved securely');
      // Clear form after saving
      setCardNumber('');
      setCvv('');
    } catch (error) {
      Alert.alert('Error', 'Failed to save card details');
      console.error(error);
    }
  };

  return (
    <View>
      <TextInput
        secureTextEntry
        keyboardType="number-pad"
        maxLength={16}
        value={cardNumber}
        onChangeText={setCardNumber}
        placeholder="Card Number"
      />
      <TextInput
        secureTextEntry
        keyboardType="number-pad"
        maxLength={3}
        value={cvv}
        onChangeText={setCvv}
        placeholder="CVV"
      />
      <Button title="Save Card Details" onPress={saveCardDetails} />
    </View>
  );
}`,
    vulnerableCode: `import React, { useState } from 'react';
import { View, Button, TextInput, Alert } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

export default function CreditCardScreen() {
  const [cardNumber, setCardNumber] = useState('');
  const [cvv, setCvv] = useState('');

  const saveCardDetails = async () => {
    try {
      // Store card info in AsyncStorage
      await AsyncStorage.setItem(
        'paymentDetails',
        JSON.stringify({
          cardNumber: cardNumber,
          cvv: cvv
        })
      );
      
      Alert.alert('Success', 'Card details saved');
      
      // Clear form after saving
      setCardNumber('');
      setCvv('');
    } catch (error) {
      Alert.alert('Error', 'Failed to save card details');
    }
  };

  return (
    <View>
      <TextInput
        value={cardNumber}
        onChangeText={setCardNumber}
        placeholder="Card Number"
      />
      <TextInput
        value={cvv}
        onChangeText={setCvv}
        placeholder="CVV"
      />
      <Button title="Save Card Details" onPress={saveCardDetails} />
    </View>
  );
}`,
    answer: 'secure',
    explanation: "The secure implementation uses SecureStore which encrypts data and stores it in the device's secure keychain/keystore, making it much harder for attackers to access sensitive information. It also uses secureTextEntry for input fields to prevent screen capture, implements input validation, and specifies WHEN_UNLOCKED to prevent access when the device is locked. The vulnerable implementation uses AsyncStorage which stores data unencrypted in the app's data directory, doesn't use secureTextEntry, and lacks input validation, making it vulnerable to data theft if the device is compromised or the app's storage is accessed."
  },
  {
    id: 'mobile-security-2',
    title: 'Certificate Pinning in Android',
    description: 'Review this Android network security configuration. Is it properly implementing certificate pinning?',
    difficulty: 'hard',
    category: 'Mobile Security',
    languages: ['Java', 'Android'],
    type: 'single',
    vulnerabilityType: 'Insecure Communication',
    code: `// AndroidManifest.xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.secureapp">
    
    <application
        android:networkSecurityConfig="@xml/network_security_config"
        ... >
        <!-- App components -->
    </application>
</manifest>

// res/xml/network_security_config.xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2023-01-01">
            <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
            <!-- Backup pin -->
            <pin digest="SHA-256">fwza0LRMXouZHRC8Ei+4PyuldPDcf3UKgO/04cDM1oE=</pin>
        </pin-set>
        <trustkit-config enforcePinning="true" />
    </domain-config>
    
    <!-- Allow cleartext traffic for specific domains -->
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="false">legacy.example.org</domain>
    </domain-config>
    
    <!-- Default configuration -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>`,
    answer: true,
    explanation: "This implementation correctly uses certificate pinning with the Android network security configuration. It includes multiple positive security aspects: 1) It pins SSL certificates for the main API domain using SHA-256 hashes, 2) It includes a backup pin which is good practice in case the primary certificate needs to change, 3) It enforces certificate pinning by setting enforcePinning to true, 4) It disables cleartext traffic by default but explicitly allows it only for a specific legacy domain, and 5) It sets an expiration date for the pins to ensure they're updated periodically. These measures help prevent MITM attacks even if an attacker has installed a rogue CA certificate on the device."
  }
];
