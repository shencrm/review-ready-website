
import { Challenge } from './challenge-types';

export const hostSecurityChallenges: Challenge[] = [
  {
    id: 'host-security-1',
    title: 'Linux Privilege Escalation',
    description: 'Review this Bash script. What security vulnerability could lead to privilege escalation?',
    difficulty: 'hard',
    category: 'Operating System Security',
    languages: ['Bash'],
    type: 'single',
    vulnerabilityType: 'SUID Binary',
    code: `#!/bin/bash
# Backup script that runs as a cron job

# Configuration file with backup settings
CONFIG_FILE="/etc/backup_config.conf"

# Get backup source and destination from config file
source "$CONFIG_FILE"

# Log file for backup operations
LOG_FILE="/var/log/backup.log"

# Function to log messages
log_message() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Create backup directory if it doesn't exist
if [ ! -d "$BACKUP_DEST" ]; then
  mkdir -p "$BACKUP_DEST"
  log_message "Created backup directory: $BACKUP_DEST"
fi

# Run backup command
log_message "Starting backup from $BACKUP_SOURCE to $BACKUP_DEST"
tar -czf "$BACKUP_DEST/backup-$(date '+%Y%m%d').tar.gz" "$BACKUP_SOURCE"

# Check if backup was successful
if [ $? -eq 0 ]; then
  log_message "Backup completed successfully"
  
  # Clean up old backups (keep last 7 days)
  find "$BACKUP_DEST" -name "backup-*.tar.gz" -mtime +7 -delete
  log_message "Cleaned up old backups"
else
  log_message "ERROR: Backup failed!"
fi

# Set ownership of the script as root:root
# chmod 4755 /usr/local/bin/backup.sh`,
    answer: false,
    explanation: "This script has multiple security vulnerabilities that could lead to privilege escalation: 1) It's set with SUID permissions (4755), allowing it to run with root privileges regardless of who executes it, 2) It sources a potentially user-accessible configuration file without validation, allowing attackers to inject malicious commands via the BACKUP_SOURCE and BACKUP_DEST variables, 3) It uses these untrusted variables directly in commands like tar and mkdir, enabling command injection, and 4) The tar command doesn't use absolute paths or validate the backup source, making it vulnerable to symlink attacks. An attacker could modify the configuration file to execute arbitrary commands with root privileges, leading to complete system compromise."
  }
];
