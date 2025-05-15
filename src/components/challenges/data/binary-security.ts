
import { Challenge } from './challenge-types';

export const binarySecurityChallenges: Challenge[] = [
  {
    id: 'binary-security-1',
    title: 'Buffer Overflow Protection',
    description: 'Compare these two C functions that handle user input. Which one is protected against buffer overflow?',
    difficulty: 'hard',
    category: 'Binary Security',
    languages: ['C'],
    type: 'comparison',
    vulnerabilityType: 'Buffer Overflow',
    secureCode: `#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_user_input(const char* input) {
    // Check input length before processing
    if (!input || strlen(input) > 1024) {
        fprintf(stderr, "Input too long or invalid\\n");
        return;
    }
    
    // Allocate buffer with exact required size
    char* buffer = (char*)malloc(strlen(input) + 1);
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed\\n");
        return;
    }
    
    // Use strncpy to safely copy into allocated buffer
    strncpy(buffer, input, strlen(input));
    buffer[strlen(input)] = '\\0'; // Ensure null termination
    
    // Process the buffer...
    printf("Processing: %s\\n", buffer);
    
    // Clean up
    free(buffer);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\\n", argv[0]);
        return 1;
    }
    
    process_user_input(argv[1]);
    return 0;
}`,
    vulnerableCode: `#include <stdio.h>
#include <string.h>

void process_user_input(const char* input) {
    // Fixed-size buffer on the stack
    char buffer[128];
    
    // Unsafe copy of input into buffer
    strcpy(buffer, input);
    
    // Process the buffer...
    printf("Processing: %s\\n", buffer);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\\n", argv[0]);
        return 1;
    }
    
    process_user_input(argv[1]);
    return 0;
}`,
    answer: 'secure',
    explanation: "The secure implementation protects against buffer overflow through multiple safeguards: 1) It checks input length before processing, 2) It dynamically allocates memory with the exact required size based on the input length, 3) It uses strncpy() with proper length control instead of strcpy(), 4) It explicitly ensures null termination of the string, and 5) It properly frees the memory when done. The vulnerable implementation uses a fixed-size stack buffer with strcpy() which doesn't check boundaries, allowing attackers to overflow the buffer and potentially overwrite the return address or other stack variables, enabling code execution attacks."
  },
  {
    id: 'binary-security-2',
    title: 'Format String Vulnerability',
    description: 'This C code logs user input. Is it vulnerable to format string attacks?',
    difficulty: 'medium',
    category: 'Binary Security',
    languages: ['C'],
    type: 'single',
    vulnerabilityType: 'Format String',
    code: `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void log_access(const char* username) {
    time_t now = time(NULL);
    char time_buffer[64];
    
    // Format the current time
    strftime(time_buffer, sizeof(time_buffer), 
             "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    // Log the access to stdout
    printf("[%s] User access: ");
    printf(username);
    printf("\\n");
    
    // Also log to a file
    FILE* logfile = fopen("access.log", "a");
    if (logfile) {
        fprintf(logfile, "[%s] User access: %s\\n", 
                time_buffer, username);
        fclose(logfile);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <username>\\n", argv[0]);
        return 1;
    }
    
    log_access(argv[1]);
    return 0;
}`,
    answer: false,
    explanation: "This code is vulnerable to format string attacks because it passes the user-controlled input (username) directly as the format string to printf(). An attacker could provide input containing format specifiers like '%x' or '%n' to leak memory contents or even write to memory. The correct way to log the username would be to use printf(\"[%s] User access: %s\\n\", time_buffer, username) with '%s' as the format specifier for the user input. Note that the file logging (fprintf) is done correctly because it uses a proper format string."
  }
];
