
import { Challenge } from './challenge-types';

export const binarySecurityChallenges: Challenge[] = [
  {
    id: 'binary-security-1',
    title: 'Buffer Overflow Prevention in C',
    description: 'Compare these two C functions that process user input. Which one prevents buffer overflow vulnerabilities?',
    difficulty: 'hard',
    category: 'Binary Security',
    languages: ['C'],
    type: 'comparison',
    vulnerabilityType: 'Buffer Overflow',
    secureCode: `#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT_SIZE 256

void processInput(const char* input) {
    char buffer[MAX_INPUT_SIZE];
    
    // Copy only up to MAX_INPUT_SIZE-1 bytes to leave room for null terminator
    strncpy(buffer, input, MAX_INPUT_SIZE - 1);
    
    // Ensure null termination
    buffer[MAX_INPUT_SIZE - 1] = '\\0';
    
    printf("Processing input: %s\\n", buffer);
    
    // Process the input safely...
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input>\\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    // Validate input length
    if (strlen(argv[1]) >= MAX_INPUT_SIZE) {
        fprintf(stderr, "Input too long (max %d characters)\\n", MAX_INPUT_SIZE - 1);
        return EXIT_FAILURE;
    }
    
    processInput(argv[1]);
    return EXIT_SUCCESS;
}`,
    vulnerableCode: `#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void processInput(const char* input) {
    char buffer[128];
    
    // Copy directly without size check
    strcpy(buffer, input);
    
    printf("Processing input: %s\\n", buffer);
    
    // Process the input...
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input>\\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    processInput(argv[1]);
    return EXIT_SUCCESS;
}`,
    answer: 'secure',
    explanation: "The secure implementation prevents buffer overflow through several measures: 1) It uses strncpy() instead of strcpy() to limit the number of bytes copied, 2) It explicitly ensures null termination by setting the last character to '\\0', 3) It validates input length before processing, rejecting inputs that exceed the buffer size, and 4) It defines a clear MAX_INPUT_SIZE constant. The vulnerable code uses strcpy() which will continue copying past the end of the buffer if the input is longer than 128 bytes, potentially overwriting adjacent memory, corrupting the stack, and enabling exploitation techniques like return-oriented programming (ROP)."
  },
  {
    id: 'binary-security-2',
    title: 'Format String Vulnerability',
    description: 'This C program logs user input. Does it contain any security vulnerabilities?',
    difficulty: 'medium',
    category: 'Binary Security',
    languages: ['C'],
    type: 'single',
    vulnerabilityType: 'Format String Vulnerability',
    code: `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void logUserInput(const char* username, const char* input) {
    time_t now = time(NULL);
    char timestamp[26];
    
    // Format timestamp
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    // Log the user input to console
    printf("[%s] User %s provided input: ", timestamp, username);
    printf(input);
    printf("\\n");
    
    // Also log to file
    FILE* logfile = fopen("user_activity.log", "a");
    if (logfile) {
        fprintf(logfile, "[%s] User %s provided input: ", timestamp, username);
        fprintf(logfile, input);
        fprintf(logfile, "\\n");
        fclose(logfile);
    }
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <input>\\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    const char* username = argv[1];
    const char* input = argv[2];
    
    logUserInput(username, input);
    
    return EXIT_SUCCESS;
}`,
    answer: false,
    explanation: "This code contains format string vulnerabilities in both printf(input) and fprintf(logfile, input) calls. Instead of using printf(input), which interprets input as a format string, it should use printf(\"%s\", input) to treat input as data only. When input is used as a format string, an attacker can provide format specifiers like %x, %s, or %n to read from or write to memory. This can lead to information disclosure (reading memory values), crashes, or even arbitrary code execution. The vulnerability exists in both the console logging and file logging sections."
  }
];
