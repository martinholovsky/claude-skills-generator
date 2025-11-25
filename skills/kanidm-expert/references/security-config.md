# Kanidm Security Configuration Guide

This guide provides comprehensive security configuration examples for Kanidm, including MFA setup, WebAuthn, password policies, credential policies, and security hardening.

---

## Table of Contents

1. [WebAuthn/FIDO2 Setup](#webauthnfido2-setup)
2. [TOTP Configuration](#totp-configuration)
3. [Password Policies](#password-policies)
4. [Credential Policies](#credential-policies)
5. [Account Lockout Policies](#account-lockout-policies)
6. [Audit Logging](#audit-logging)
7. [TLS Configuration](#tls-configuration)
8. [Backup & Recovery](#backup--recovery)
9. [Security Monitoring](#security-monitoring)
10. [Incident Response](#incident-response)

---

## WebAuthn/FIDO2 Setup

### User WebAuthn Enrollment

WebAuthn enrollment is performed via the Kanidm web UI. Users cannot enroll WebAuthn devices via CLI.

**Enrollment Process:**

1. User logs in to web UI: `https://idm.example.com/`
2. Navigate to Account Settings → Security Keys
3. Click "Add Security Key"
4. Follow browser prompts to register FIDO2 device:
   - Insert YubiKey and touch when prompted
   - Use TouchID/Windows Hello on supported devices
   - Use Android/iOS biometrics on mobile
5. Name the security key (e.g., "YubiKey 5 NFC", "iPhone TouchID")
6. Key is now registered and required for authentication

**Supported FIDO2 Devices:**
- YubiKey 5 Series (USB-A, USB-C, NFC, Nano)
- Google Titan Security Keys
- Feitian BioPass FIDO2
- Windows Hello (Windows 10/11)
- TouchID (macOS)
- Android/iOS platform authenticators

### Enforcing WebAuthn for Groups

```bash
# Create credential policy requiring WebAuthn
kanidm credential-policy create webauthn_required \
  --require-webauthn

# Apply to privileged groups
kanidm group create admins "System Administrators"
kanidm group create operators "Infrastructure Operators"

kanidm credential-policy apply webauthn_required admins
kanidm credential-policy apply webauthn_required operators

# Add users to groups (they MUST have WebAuthn enrolled)
kanidm group add-members admins alice
kanidm group add-members operators bob

# Verify policy
kanidm credential-policy get webauthn_required
```

### WebAuthn-Only Authentication

```bash
# Disable password authentication entirely for ultra-secure accounts
kanidm credential-policy create webauthn_only \
  --require-webauthn \
  --disable-password

# Apply to break-glass admin account
kanidm credential-policy apply webauthn_only admin

# WARNING: Ensure admin has WebAuthn enrolled BEFORE applying!
# If locked out, use: kanidmd recover-account admin
```

### Managing User WebAuthn Devices

```bash
# List user's registered WebAuthn devices (admin only)
kanidm person get alice | grep webauthn

# User can view their own devices via web UI

# Remove compromised WebAuthn device (emergency)
# Currently must be done via web UI or direct database access
# Contact Kanidm support for CLI commands
```

### WebAuthn Backup Strategies

**Problem:** What if user loses their FIDO2 device?

**Solutions:**

1. **Multiple WebAuthn Devices** (Recommended)
   - Enroll 2-3 FIDO2 devices per user
   - Example: Primary YubiKey + Backup YubiKey + Phone biometrics
   - Store backup key securely (safe, locked drawer)

2. **TOTP as Backup**
   - Configure TOTP in addition to WebAuthn
   - Store TOTP secret in password manager
   - Less secure than WebAuthn, but prevents lockout

3. **Recovery Codes** (Future Feature)
   - One-time use recovery codes
   - Print and store securely
   - Not yet available in Kanidm 1.1

4. **Admin Recovery**
   ```bash
   # Admin can reset user's credentials (last resort)
   kanidm person credential reset alice
   # User must re-enroll WebAuthn/TOTP
   ```

---

## TOTP Configuration

### User TOTP Enrollment

TOTP enrollment is performed via Kanidm web UI or CLI.

**Web UI Enrollment:**
1. Log in to `https://idm.example.com/`
2. Navigate to Account Settings → TOTP
3. Click "Add TOTP Device"
4. Scan QR code with authenticator app:
   - Google Authenticator
   - Microsoft Authenticator
   - Authy
   - 1Password
   - Bitwarden
5. Enter verification code
6. TOTP is now active

**CLI Enrollment:**
```bash
# User generates TOTP enrollment
kanidm person totp generate alice

# Output: QR code URL and secret
# Scan QR code or manually enter secret in authenticator app

# Verify TOTP setup
kanidm person totp verify alice 123456

# Enable TOTP
kanidm person totp enable alice
```

### TOTP as Backup to WebAuthn

```bash
# Best practice: Require WebAuthn, allow TOTP as fallback
kanidm credential-policy create webauthn_totp_backup \
  --require-webauthn \
  --allow-totp

# Apply to user groups
kanidm credential-policy apply webauthn_totp_backup developers
kanidm credential-policy apply webauthn_totp_backup support_staff

# Users must enroll WebAuthn first, can optionally add TOTP
```

### Enforcing TOTP for All Users

```bash
# Require TOTP for all accounts
kanidm credential-policy create totp_required \
  --require-totp

# Apply globally (default policy)
kanidm credential-policy apply totp_required idm_people

# All users must enroll TOTP before next login
```

### TOTP Management

```bash
# List user's TOTP devices
kanidm person totp list alice

# Remove TOTP device
kanidm person totp remove alice

# Reset TOTP (if user loses device)
kanidm person totp reset alice
# User must re-enroll TOTP
```

---

## Password Policies

### Basic Password Policy

```bash
# Standard password policy for regular users
kanidm credential-policy create standard_password \
  --minimum-length 14 \
  --require-uppercase \
  --require-lowercase \
  --require-number \
  --password-history 12

# Apply to all users
kanidm credential-policy apply standard_password idm_people
```

### High-Security Password Policy

```bash
# Strict policy for privileged accounts
kanidm credential-policy create high_security_password \
  --minimum-length 16 \
  --require-uppercase \
  --require-lowercase \
  --require-number \
  --require-symbol \
  --password-history 24 \
  --minimum-age 1  # Can't change password more than once per day

# Apply to privileged groups
kanidm credential-policy apply high_security_password admins
kanidm credential-policy apply high_security_password security_team
```

### Service Account Password Policy

```bash
# Long, complex passwords for service accounts
kanidm credential-policy create service_account_password \
  --minimum-length 32 \
  --require-uppercase \
  --require-lowercase \
  --require-number \
  --require-symbol \
  --password-history 6

# Apply to service account group
kanidm group create service_accounts "Application Service Accounts"
kanidm credential-policy apply service_account_password service_accounts

# Add service accounts
kanidm service-account create gitlab_runner "GitLab CI Runner"
kanidm group add-members service_accounts gitlab_runner
```

### Password Complexity Examples

```bash
# Generate strong password (external tool)
openssl rand -base64 32

# Example strong passwords
# Standard (14 chars): Tr0ub4dor&3!@#
# High Security (16 chars): C0mpl3x!P@ssw0rd#2025
# Service Account (32 chars): aB3$dE6@fG9#hI2!jK5%lM8&nO1*pQ4^

# Test password against policy
kanidm person credential set-password alice
# Enter password, Kanidm validates against policy
# Rejection examples:
# - "password123" → Too short, no uppercase, no symbols
# - "PASSWORD123!" → No lowercase
# - "Password!" → Too short
# - "Password123" → No symbols (if required)
```

### Password Expiration (Not Recommended)

Kanidm follows modern security guidance: **do not enforce password expiration** for human users. Password expiration leads to:
- Predictable password patterns (Summer2024, Summer2025)
- Passwords written down
- User frustration
- No measurable security improvement

**Better alternatives:**
1. Enforce strong password policies
2. Require MFA (WebAuthn/TOTP)
3. Monitor for compromised credentials
4. Educate users on password managers

**Service account exception:**
```bash
# Rotate service account credentials quarterly
# Manual process - set calendar reminder
kanidm service-account credential set-password gitlab_runner
# Document in change log
```

---

## Credential Policies

### Comprehensive Credential Policy

```bash
# Full-featured credential policy
kanidm credential-policy create comprehensive \
  --minimum-length 16 \
  --require-uppercase \
  --require-lowercase \
  --require-number \
  --require-symbol \
  --password-history 12 \
  --require-webauthn \
  --allow-totp

# Apply to specific group
kanidm group create executives "Executive Leadership"
kanidm credential-policy apply comprehensive executives
```

### Credential Policy Inheritance

```bash
# Default policy for all users
kanidm credential-policy create default_policy \
  --minimum-length 14 \
  --require-uppercase \
  --require-lowercase \
  --require-number \
  --password-history 12

kanidm credential-policy apply default_policy idm_people

# Override for privileged users (more strict)
kanidm credential-policy create privileged_policy \
  --minimum-length 16 \
  --require-uppercase \
  --require-lowercase \
  --require-number \
  --require-symbol \
  --password-history 24 \
  --require-webauthn

kanidm credential-policy apply privileged_policy admins

# admins inherit privileged_policy (overrides default_policy)
```

### Viewing Credential Policies

```bash
# List all credential policies
kanidm credential-policy list

# View specific policy
kanidm credential-policy get standard_password

# Check which policy applies to user
kanidm person get alice | grep credential-policy

# Check which policy applies to group
kanidm group get developers | grep credential-policy
```

### Removing Credential Policies

```bash
# Remove policy from group
kanidm credential-policy remove-from-group developers standard_password

# Delete credential policy (if unused)
kanidm credential-policy delete old_policy
```

---

## Account Lockout Policies

### Basic Account Lockout

```bash
# Lock account after 5 failed attempts for 1 hour
kanidm account-policy set-lockout \
  --threshold 5 \
  --duration 3600

# Applies globally to all accounts
```

### Progressive Lockout

```bash
# Increasing lockout duration
# First 5 failures: 15 minutes
kanidm account-policy set-lockout \
  --threshold 5 \
  --duration 900

# Monitor for persistent failures
journalctl -u kanidmd | grep "authentication failure"

# Permanent lockout after 10 total failures (requires admin unlock)
# Note: Configure this via server.toml or custom policy
```

### Unlocking Locked Accounts

```bash
# Admin unlocks user account
kanidm account unlock alice

# View locked accounts
kanidm account list | grep locked

# Check lockout reason
kanidm person get alice | grep lock
```

### Monitoring Failed Logins

```bash
# Real-time monitoring
journalctl -u kanidmd -f | grep "authentication failure"

# Export failed login attempts
kanidm audit-log export --since "2025-11-01" --filter "auth_failure" > failures.json

# Analyze failed attempts
cat failures.json | jq '.[] | select(.event_type == "authentication_failure") | .user'

# Alert on suspicious patterns
# Configure SIEM integration or monitoring tool
```

### Temporary Account Lockout (Administrative)

```bash
# Manually lock account (immediate effect)
kanidm account lock alice --reason "Security investigation in progress"

# Unlock when investigation complete
kanidm account unlock alice

# Lock service account during rotation
kanidm account lock gitlab_runner --reason "Credential rotation"
kanidm service-account credential set-password gitlab_runner
kanidm account unlock gitlab_runner
```

---

## Audit Logging

### Enable Comprehensive Audit Logging

```toml
# /etc/kanidm/server.toml
log_level = "info"  # Standard logging
# log_level = "debug"  # Detailed logging (use for troubleshooting)

# Audit events are logged to systemd journal
```

### Export Audit Logs

```bash
# Export all audit events
kanidm audit-log export > audit-full.json

# Export events from specific date
kanidm audit-log export --since "2025-11-01" > audit-november.json

# Export events for specific user
kanidm audit-log export --filter "user:alice" > audit-alice.json

# Export authentication events only
kanidm audit-log export --filter "event:authentication" > audit-auth.json

# Export format options
kanidm audit-log export --format json > audit.json
kanidm audit-log export --format csv > audit.csv
```

### Key Audit Events

**Authentication Events:**
- Successful login
- Failed login attempts
- MFA enrollment/removal
- Password changes
- Account lockouts

**Authorization Events:**
- Group membership changes
- Permission grants/revocations
- Role assignments

**Administrative Events:**
- Account creation/deletion
- Group creation/deletion
- Policy changes
- OAuth2 client registration
- RADIUS configuration changes

**Security Events:**
- Privilege escalation attempts
- Unauthorized access attempts
- Credential resets
- API token generation

### Audit Log Analysis

```bash
# Count authentication failures by user
journalctl -u kanidmd --since "1 week ago" | grep "authentication failure" | \
  awk '{print $NF}' | sort | uniq -c | sort -rn

# Monitor for brute force attempts
journalctl -u kanidmd -f | grep "authentication failure" | \
  awk '{print $NF}' | sort | uniq -c | \
  awk '$1 > 10 {print "ALERT: Possible brute force against user " $2}'

# Export to SIEM
journalctl -u kanidmd -o json > /var/log/kanidm/audit.jsonl
# Configure filebeat/fluentd to ship to SIEM
```

### Log Retention

```bash
# Configure systemd journal retention
# /etc/systemd/journald.conf
[Journal]
MaxRetentionSec=365d  # Keep logs for 1 year
MaxFileSec=1month     # Rotate monthly

# Restart journald
systemctl restart systemd-journald

# Archive logs to long-term storage
journalctl -u kanidmd --since "2025-01-01" --until "2025-01-31" > kanidm-jan2025.log
gzip kanidm-jan2025.log
# Move to archive storage
```

---

## TLS Configuration

### Generate TLS Certificates

**Production (CA-Signed Certificate):**

```bash
# Use Let's Encrypt with certbot
apt install certbot
certbot certonly --standalone -d idm.example.com

# Certificates location
# /etc/letsencrypt/live/idm.example.com/fullchain.pem
# /etc/letsencrypt/live/idm.example.com/privkey.pem

# Configure Kanidm to use Let's Encrypt certs
# /etc/kanidm/server.toml
tls_chain = "/etc/letsencrypt/live/idm.example.com/fullchain.pem"
tls_key = "/etc/letsencrypt/live/idm.example.com/privkey.pem"

# Auto-renewal
certbot renew --deploy-hook "systemctl restart kanidmd"
```

**Development (Self-Signed Certificate):**

```bash
# Generate self-signed certificate (DEV/TEST ONLY)
kanidmd cert-generate \
  --ca-path /data/ca.pem \
  --cert-path /data/cert.pem \
  --key-path /data/key.pem \
  --domain idm.example.com

# Configure Kanidm
# /etc/kanidm/server.toml
tls_chain = "/data/cert.pem"
tls_key = "/data/key.pem"

# Trust self-signed CA on clients
cp /data/ca.pem /usr/local/share/ca-certificates/kanidm-ca.crt
update-ca-certificates
```

### TLS Hardening

```toml
# /etc/kanidm/server.toml
# TLS 1.2 minimum (TLS 1.3 preferred)
# Kanidm automatically uses strong cipher suites

# Verify TLS configuration
tls_chain = "/etc/letsencrypt/live/idm.example.com/fullchain.pem"
tls_key = "/etc/letsencrypt/live/idm.example.com/privkey.pem"

# Test with
openssl s_client -connect idm.example.com:8443 -tls1_2
openssl s_client -connect idm.example.com:8443 -tls1_3
```

### TLS Certificate Monitoring

```bash
# Check certificate expiration
echo | openssl s_client -connect idm.example.com:8443 2>/dev/null | \
  openssl x509 -noout -dates

# Monitor certificate validity
cat > /usr/local/bin/check-kanidm-cert.sh <<'EOF'
#!/bin/bash
DAYS_UNTIL_EXPIRY=$(echo | openssl s_client -connect idm.example.com:8443 2>/dev/null | \
  openssl x509 -noout -checkend $((30*86400)))

if [ $? -eq 1 ]; then
  echo "ALERT: Kanidm TLS certificate expires in less than 30 days!"
  # Send alert to monitoring system
fi
EOF

chmod +x /usr/local/bin/check-kanidm-cert.sh

# Cron job
0 0 * * * /usr/local/bin/check-kanidm-cert.sh
```

### LDAPS TLS Configuration

```toml
# /etc/kanidm/server.toml
# LDAPS automatically uses same TLS config as HTTPS
ldapbindaddress = "[::]:3636"

# TLS is REQUIRED for LDAP
# Plain LDAP (port 389) is NOT supported (by design, for security)
```

---

## Backup & Recovery

### Automated Backup Script

```bash
#!/bin/bash
# /usr/local/bin/kanidm-backup.sh

set -euo pipefail

BACKUP_DIR="/data/backups"
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/kanidm-${DATE}.json"
RETENTION_DAYS=30

# Create backup directory
mkdir -p "${BACKUP_DIR}"

# Perform online backup
echo "Starting Kanidm backup: ${BACKUP_FILE}"
kanidmd backup "${BACKUP_FILE}"

# Verify backup
if [ -f "${BACKUP_FILE}" ]; then
  SIZE=$(stat -f%z "${BACKUP_FILE}" 2>/dev/null || stat -c%s "${BACKUP_FILE}")
  echo "Backup completed: ${BACKUP_FILE} (${SIZE} bytes)"
else
  echo "ERROR: Backup failed!"
  exit 1
fi

# Compress backup
gzip "${BACKUP_FILE}"
echo "Backup compressed: ${BACKUP_FILE}.gz"

# Delete old backups
find "${BACKUP_DIR}" -name "kanidm-*.json.gz" -mtime +${RETENTION_DAYS} -delete
echo "Old backups deleted (retention: ${RETENTION_DAYS} days)"

# Copy to off-site storage (optional)
# aws s3 cp "${BACKUP_FILE}.gz" s3://kanidm-backups/
# rclone copy "${BACKUP_FILE}.gz" remote:kanidm-backups/

echo "Backup complete!"
```

```bash
# Install backup script
chmod +x /usr/local/bin/kanidm-backup.sh

# Cron job: Daily at 2 AM
crontab -e
0 2 * * * /usr/local/bin/kanidm-backup.sh >> /var/log/kanidm-backup.log 2>&1
```

### Manual Backup

```bash
# Online backup (server running)
kanidmd backup /data/backups/kanidm-$(date +%Y%m%d-%H%M%S).json

# Offline backup (server stopped)
systemctl stop kanidmd
kanidmd database backup /data/backups/offline-backup.json
systemctl start kanidmd

# Backup server.toml configuration
cp /etc/kanidm/server.toml /data/backups/server.toml.$(date +%Y%m%d)
```

### Restore Procedure

```bash
# CRITICAL: Test restore procedure regularly!

# Stop Kanidm server
systemctl stop kanidmd

# Restore from backup
kanidmd database restore /data/backups/kanidm-20251119.json

# Verify database integrity
kanidmd database verify

# Start Kanidm server
systemctl start kanidmd

# Verify functionality
kanidm login --name admin
kanidm person list
kanidm group list

# Check logs for errors
journalctl -u kanidmd -n 100
```

### Disaster Recovery Testing

```bash
# Quarterly DR test procedure

# 1. Set up test environment
# - Separate VM/container
# - Same Kanidm version as production

# 2. Restore from backup
kanidmd database restore /path/to/latest/backup.json

# 3. Verify core functionality
kanidm login --name testuser
kanidm person get testuser
kanidm group list

# 4. Test authentication
# - Web UI login
# - LDAP bind test
# - OAuth2 flow test
# - RADIUS authentication test

# 5. Document results
# - Restore time: X minutes
# - Issues encountered: ...
# - Action items: ...

# 6. Update DR runbook
```

### Off-Site Backup Storage

```bash
# AWS S3 backup
aws s3 cp /data/backups/kanidm-latest.json.gz s3://kanidm-backups/

# Rclone to multiple cloud providers
rclone copy /data/backups/ aws-s3:kanidm-backups/
rclone copy /data/backups/ backblaze-b2:kanidm-backups/
rclone copy /data/backups/ google-drive:kanidm-backups/

# Encryption for off-site backups
gpg --encrypt --recipient backup@example.com kanidm-backup.json
# Upload encrypted file
```

---

## Security Monitoring

### Real-Time Monitoring

```bash
# Monitor authentication failures
journalctl -u kanidmd -f | grep "authentication failure"

# Monitor all authentication events
journalctl -u kanidmd -f | grep "authentication"

# Monitor privileged operations
journalctl -u kanidmd -f | grep -E "(admin|credential|group add|group remove)"

# Monitor LDAP queries
journalctl -u kanidmd -f | grep "ldap"

# Monitor OAuth2 token issuance
journalctl -u kanidmd -f | grep "oauth2"
```

### Alerting Rules

**Prometheus + Alertmanager Example:**

```yaml
# prometheus-alerts.yml
groups:
- name: kanidm
  rules:
  # High authentication failure rate
  - alert: KanidmHighAuthFailureRate
    expr: rate(kanidm_auth_failures_total[5m]) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High authentication failure rate"
      description: "Kanidm is experiencing high authentication failure rate ({{ $value }} failures/sec)"

  # Account lockouts
  - alert: KanidmAccountLockout
    expr: increase(kanidm_account_lockouts_total[15m]) > 5
    labels:
      severity: warning
    annotations:
      summary: "Multiple account lockouts detected"

  # Service down
  - alert: KanidmServiceDown
    expr: up{job="kanidm"} == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Kanidm service is down"
```

### SIEM Integration

```bash
# Fluentd configuration for Kanidm logs
cat > /etc/fluentd/conf.d/kanidm.conf <<EOF
<source>
  @type systemd
  path /var/log/journal
  filters [{ "_SYSTEMD_UNIT": "kanidmd.service" }]
  tag kanidm
  read_from_head true
</source>

<match kanidm>
  @type elasticsearch
  host elasticsearch.example.com
  port 9200
  logstash_format true
  logstash_prefix kanidm
</match>
EOF

# Restart fluentd
systemctl restart fluentd
```

### Security Metrics

**Key metrics to monitor:**

1. **Authentication metrics:**
   - Successful logins per minute
   - Failed logins per minute
   - Failed login ratio
   - MFA enrollment rate
   - WebAuthn usage rate

2. **Account metrics:**
   - New account creations
   - Account lockouts
   - Dormant accounts
   - Privileged accounts

3. **Operational metrics:**
   - API request rate
   - LDAP query rate
   - OAuth2 token issuance rate
   - RADIUS authentication rate

4. **Security events:**
   - Credential resets
   - Policy changes
   - Group membership changes
   - Privilege escalations

---

## Incident Response

### Security Incident Playbook

**1. Account Compromise Detected**

```bash
# Immediate actions
# 1. Lock compromised account
kanidm account lock alice --reason "Security incident - compromised credentials"

# 2. Revoke all sessions/tokens
kanidm person session revoke-all alice

# 3. Review recent activity
kanidm audit-log export --filter "user:alice" --since "7 days ago" > alice-activity.json

# 4. Check for unauthorized changes
cat alice-activity.json | jq '.[] | select(.event_type == "group_add" or .event_type == "permission_grant")'

# 5. Reset credentials
kanidm person credential reset alice

# 6. Notify user via out-of-band channel (phone, in-person)

# 7. Force WebAuthn re-enrollment
kanidm credential-policy apply webauthn_required_temp alice

# 8. Document incident
echo "Incident: Account compromise - alice - $(date)" >> /var/log/security-incidents.log
```

**2. Brute Force Attack Detected**

```bash
# Identify attackers
journalctl -u kanidmd --since "1 hour ago" | grep "authentication failure" | \
  awk '{print $NF}' | sort | uniq -c | sort -rn | head -20

# Block source IPs at firewall
ufw deny from 203.0.113.50
ufw deny from 203.0.113.51

# Review account lockout policy
kanidm account-policy get-lockout

# Increase lockout threshold temporarily
kanidm account-policy set-lockout --threshold 3 --duration 7200

# Monitor for continued attempts
journalctl -u kanidmd -f | grep "authentication failure"

# Document incident
```

**3. Unauthorized Privilege Escalation**

```bash
# User added to admin group without authorization
# 1. Remove from privileged group
kanidm group remove-members admins bob

# 2. Investigate who made the change
kanidm audit-log export --filter "group:admins" --since "24 hours ago" > admin-changes.json
cat admin-changes.json | jq '.[] | select(.event_type == "group_add")'

# 3. Lock attacker account
kanidm account lock mallory --reason "Unauthorized privilege escalation attempt"

# 4. Review all group memberships
kanidm group get admins
kanidm group get operators

# 5. Implement additional controls
# - Require approval for admin group changes
# - Enable audit alerts for privileged group changes
```

**4. Data Breach (LDAP Bind Password Exposed)**

```bash
# LDAP bind account credentials leaked
# 1. Immediately rotate credentials
kanidm service-account credential set-password ldap_bind
# Generate new strong password

# 2. Update all systems using LDAP bind
# - Update Grafana ldap.toml
# - Update NextCloud config
# - Update other LDAP clients

# 3. Review LDAP access logs
journalctl -u kanidmd | grep "ldap_bind" > ldap-access.log

# 4. Check for unauthorized access
grep "ldap_bind" ldap-access.log | grep -v "expected.ip.address"

# 5. Consider creating new LDAP bind account
kanidm service-account create ldap_bind_new "New LDAP Bind Account"
# Update all systems to use new account
# Delete old account after migration
kanidm service-account delete ldap_bind

# 6. Document incident and lessons learned
```

### Post-Incident Review

```markdown
# Security Incident Post-Mortem Template

## Incident Summary
- Date/Time: 2025-11-19 14:30 UTC
- Severity: Medium
- Type: Account Compromise

## Timeline
- 14:30: Unusual login activity detected
- 14:35: Account locked by security team
- 14:40: User notified via phone
- 15:00: Credentials reset, WebAuthn re-enrolled
- 15:30: Incident resolved

## Root Cause
- User clicked phishing link
- Password reused from breached service

## Actions Taken
- Account locked immediately
- All sessions revoked
- Credentials reset
- WebAuthn enforced

## Lessons Learned
- Need security awareness training
- Implement password compromise monitoring
- Enforce WebAuthn for all users (not just admins)

## Action Items
- [ ] Deploy security awareness training (Due: 2025-12-01)
- [ ] Integrate HaveIBeenPwned API (Due: 2025-12-15)
- [ ] Roll out WebAuthn to all users (Due: 2026-01-15)
```

---

## Security Best Practices Summary

### Critical Security Controls

1. **Authentication:**
   - ✅ WebAuthn required for privileged accounts
   - ✅ TOTP enabled as backup
   - ✅ Strong password policies (14+ characters)
   - ✅ Account lockout after 5 failures

2. **Authorization:**
   - ✅ Principle of least privilege
   - ✅ Regular access reviews (quarterly)
   - ✅ Group-based access control
   - ✅ Audit privileged operations

3. **Network Security:**
   - ✅ TLS for all connections
   - ✅ Strong RADIUS secrets (32+ characters)
   - ✅ LDAPS only (no plain LDAP)
   - ✅ Firewall restrictions

4. **Operational Security:**
   - ✅ Daily automated backups
   - ✅ Quarterly DR testing
   - ✅ Off-site backup storage
   - ✅ Comprehensive audit logging

5. **Monitoring:**
   - ✅ Real-time authentication monitoring
   - ✅ SIEM integration
   - ✅ Alerting on security events
   - ✅ Incident response procedures

### Security Checklist

Before going to production:
- [ ] WebAuthn enforced for all admins
- [ ] Strong password policies configured
- [ ] Account lockout enabled
- [ ] TLS certificates from trusted CA
- [ ] Automated backups tested
- [ ] Restore procedure documented and tested
- [ ] Audit logging enabled
- [ ] Monitoring and alerting configured
- [ ] Firewall rules configured
- [ ] Incident response plan documented
- [ ] Security team trained on procedures

This security configuration guide provides comprehensive protection for Kanidm deployments. Always test security controls in non-production environments before deploying to production.
