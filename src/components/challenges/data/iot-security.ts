
import { Challenge } from './challenge-types';

export const iotSecurityChallenges: Challenge[] = [
  {
    id: 'iot-security-1',
    title: 'IoT Device Authentication',
    description: 'Compare these two Python implementations for IoT device authentication. Which one is secure?',
    difficulty: 'hard',
    category: 'IoT Security',
    languages: ['Python'],
    type: 'comparison',
    vulnerabilityType: 'Weak Authentication',
    secureCode: `import ssl
import json
import time
import hmac
import hashlib
import uuid
from datetime import datetime
import paho.mqtt.client as mqtt

# Device credentials stored in secure environment variables or secure storage
DEVICE_ID = os.environ.get("DEVICE_ID")
DEVICE_KEY = os.environ.get("DEVICE_KEY")
MQTT_HOST = "iot-hub.example.com"
MQTT_PORT = 8883

# Generate SAS token for authentication
def generate_sas_token():
    ttl = int(time.time()) + 3600  # Token valid for 1 hour
    string_to_sign = f"{MQTT_HOST}/devices/{DEVICE_ID}\\n{ttl}"
    signature = hmac.new(
        base64.b64decode(DEVICE_KEY),
        msg=string_to_sign.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    
    encoded_signature = base64.b64encode(signature).decode('utf-8')
    token = f"SharedAccessSignature sr={MQTT_HOST}%2Fdevices%2F{DEVICE_ID}&sig={encoded_signature}&se={ttl}"
    return token

# Set up secure MQTT client with TLS
def create_secure_client():
    client = mqtt.Client(client_id=f"{DEVICE_ID}-{uuid.uuid4()}", clean_session=True)
    client.username_pw_set(username=f"{MQTT_HOST}/{DEVICE_ID}", password=generate_sas_token())
    
    # Enable TLS with server certificate validation
    client.tls_set(
        ca_certs="ca_certificate.pem",
        certfile=None,
        keyfile=None,
        cert_reqs=ssl.CERT_REQUIRED,
        tls_version=ssl.PROTOCOL_TLS,
        ciphers=None
    )
    client.tls_insecure_set(False)
    
    return client

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected successfully")
        # Send device metadata after successful connection
        client.publish(
            f"devices/{DEVICE_ID}/metadata",
            json.dumps({
                "firmware_version": "1.2.3",
                "last_updated": datetime.now().isoformat(),
                "capabilities": ["temperature", "humidity"]
            }),
            qos=1
        )
    else:
        print(f"Connection failed with code {rc}")

# Connect securely to IoT hub
client = create_secure_client()
client.on_connect = on_connect

# Set up connection and start processing messages
client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
client.loop_forever()`,
    vulnerableCode: `import json
import time
import paho.mqtt.client as mqtt

# Hardcoded credentials
DEVICE_ID = "device123"
DEVICE_PASSWORD = "password123"
MQTT_HOST = "iot.example.com"
MQTT_PORT = 1883

# Set up MQTT client
client = mqtt.Client(client_id=DEVICE_ID)
client.username_pw_set(DEVICE_ID, DEVICE_PASSWORD)

def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    # Send device metadata after connection
    client.publish(
        "devices/device123/metadata",
        json.dumps({
            "firmware": "1.0.0",
            "last_boot": time.time()
        })
    )

client.on_connect = on_connect

# Connect to MQTT broker and start processing messages
client.connect(MQTT_HOST, MQTT_PORT, 60)
client.loop_forever()`,
    answer: 'secure',
    explanation: "The secure implementation offers multiple security features: 1) It uses environment variables for sensitive credentials, 2) Implements HMAC-based SAS token authentication with expiration, 3) Uses TLS/SSL with proper certificate validation on port 8883, 4) Sets cert_reqs=ssl.CERT_REQUIRED to verify the server's identity, 5) Creates a unique client ID with UUID to prevent session hijacking, 6) Uses QoS 1 for important messages to ensure delivery. The vulnerable code has several issues: hardcoded credentials in the source code, unencrypted MQTT on port 1883, no certificate validation, static client ID, and no message delivery guarantees."
  },
  {
    id: 'iot-security-2',
    title: 'IoT Firmware Update',
    description: 'This code handles firmware updates for an IoT device. Is it implemented securely?',
    difficulty: 'hard',
    category: 'IoT Security',
    languages: ['C'],
    type: 'single',
    vulnerabilityType: 'Insecure Firmware Update',
    code: `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#define FIRMWARE_URL "http://updates.iotvendor.com/latest.bin"
#define FIRMWARE_PATH "/tmp/firmware.bin"
#define FLASH_COMMAND "/usr/bin/flash_firmware"

// Function to download firmware update
int download_firmware() {
    FILE *fp;
    CURL *curl;
    CURLcode res;
    
    fp = fopen(FIRMWARE_PATH, "wb");
    if (!fp) {
        printf("Error: Cannot create firmware file\\n");
        return 1;
    }
    
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, FIRMWARE_URL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            printf("Error: Failed to download firmware: %s\\n", 
                   curl_easy_strerror(res));
            fclose(fp);
            curl_easy_cleanup(curl);
            return 1;
        }
        
        curl_easy_cleanup(curl);
        fclose(fp);
        return 0;
    }
    
    fclose(fp);
    return 1;
}

// Function to install firmware update
int install_firmware() {
    char command[256];
    
    sprintf(command, "%s %s", FLASH_COMMAND, FIRMWARE_PATH);
    printf("Installing firmware update...\\n");
    
    return system(command);
}

int main() {
    printf("Checking for firmware updates...\\n");
    
    if (download_firmware() == 0) {
        printf("Firmware downloaded successfully\\n");
        
        if (install_firmware() == 0) {
            printf("Firmware update completed successfully\\n");
            return 0;
        } else {
            printf("Error: Firmware installation failed\\n");
            return 1;
        }
    }
    
    printf("Error: Failed to download firmware update\\n");
    return 1;
}`,
    answer: false,
    explanation: "This firmware update implementation has several security vulnerabilities: 1) It downloads firmware over HTTP instead of HTTPS, allowing for man-in-the-middle attacks, 2) It doesn't verify the firmware's integrity or authenticity with signatures or checksums, 3) It uses system() with a command built from user inputs, creating command injection risk, 4) It stores the firmware in /tmp which might be accessible to other processes, 5) It doesn't implement version checking to prevent downgrade attacks, and 6) It doesn't have rollback capability if the update fails. To be secure, it should use HTTPS, implement cryptographic signature verification, avoid system(), use secure storage, and provide fallback mechanisms."
  }
];
