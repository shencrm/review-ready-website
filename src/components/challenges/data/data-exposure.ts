
import { Challenge } from './challenge-types';

export const dataExposureChallenges: Challenge[] = [
  {
    id: 'data-exposure-1',
    title: 'API Key Exposure',
    description: 'Compare these two JavaScript files that handle API key usage in a React Native mobile app. Which one securely handles the API key?',
    difficulty: 'easy',
    category: 'Sensitive Data Exposure',
    languages: ['JavaScript', 'React Native'],
    type: 'comparison',
    vulnerabilityType: 'API Key Exposure',
    secureCode: `import { Platform } from 'react-native';
import Config from 'react-native-config';
import * as SecureStore from 'expo-secure-store';

export async function getWeatherData(city) {
  try {
    // Get API key from environment variables or secure storage
    let apiKey;
    if (Platform.OS === 'web') {
      // For web, use environment variables
      apiKey = process.env.REACT_APP_WEATHER_API_KEY;
    } else {
      // For mobile, use secure storage
      apiKey = await SecureStore.getItemAsync('weather_api_key');
    }
    
    if (!apiKey) {
      console.error('API key not available');
      return null;
    }
    
    // Make the API request with the secure key
    const response = await fetch(
      \`https://api.weatherservice.com/data?city=\${encodeURIComponent(city)}&key=\${apiKey}\`,
      { method: 'GET' }
    );
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching weather data:', error);
    return null;
  }
}`,
    vulnerableCode: `// api.js - Weather API client

// API key directly hardcoded in the source code
const API_KEY = '9a8b7c6d5e4f3g2h1i0j';

export async function getWeatherData(city) {
  try {
    const response = await fetch(
      \`https://api.weatherservice.com/data?city=\${encodeURIComponent(city)}&key=\${API_KEY}\`,
      { method: 'GET' }
    );
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching weather data:', error);
    return null;
  }
}`,
    answer: 'secure',
    explanation: "The secure version handles API keys correctly by: 1) Using environment variables for web platforms and secure storage for mobile platforms instead of hardcoding the key, 2) Checking if the key exists before making the request, and 3) Providing appropriate error handling. The vulnerable version directly hardcodes the API key in the source code, which can be extracted from the compiled app or discovered through reverse engineering."
  }
];
