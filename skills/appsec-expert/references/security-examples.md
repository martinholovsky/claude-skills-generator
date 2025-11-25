# OWASP Top 10 2025 - Detailed Security Examples

This file contains comprehensive OWASP Top 10 2025 coverage referenced from main SKILL.md Section 5.

**Research Date**: 2025-01-15

---

## A01:2025 - Broken Access Control

**Description**: Occurs when users can act outside their intended permissions, accessing resources they shouldn't.

**Common Vulnerabilities**:
- Insecure Direct Object References (IDOR)
- Missing function-level access control
- Privilege escalation (horizontal/vertical)
- CORS misconfiguration
- Forced browsing to authenticated pages

```python
# ❌ VULNERABLE: IDOR - No authorization check
@app.route('/api/users/<int:user_id>/profile')
def get_profile(user_id):
    user = User.query.get(user_id)  # Any user can view any profile!
    return jsonify(user.to_dict())

# ✅ SECURE: Authorization check
@app.route('/api/users/<int:user_id>/profile')
@require_auth()
def get_profile_secure(user_id):
    # Check if current user can access this profile
    current_user_id = request.current_user['sub']

    if current_user_id != user_id and 'admin' not in request.current_user['roles']:
        return jsonify({'error': 'Forbidden'}), 403

    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())

# ✅ SECURE: Attribute-Based Access Control (ABAC)
class AccessControl:
    """ABAC implementation"""

    @staticmethod
    def can_access_resource(user: dict, resource: dict, action: str) -> bool:
        """Check if user can perform action on resource"""

        # Owner can do anything
        if resource.get('owner_id') == user.get('id'):
            return True

        # Admin can do anything
        if 'admin' in user.get('roles', []):
            return True

        # Check specific permissions
        if action == 'read' and resource.get('is_public'):
            return True

        # Check shared access
        if user.get('id') in resource.get('shared_with', []):
            return action in ['read', 'comment']

        return False

@app.route('/api/documents/<int:doc_id>')
@require_auth()
def get_document(doc_id):
    document = Document.query.get_or_404(doc_id)

    if not AccessControl.can_access_resource(
        user=request.current_user,
        resource=document.to_dict(),
        action='read'
    ):
        return jsonify({'error': 'Forbidden'}), 403

    return jsonify(document.to_dict())
```

---

## A02:2025 - Cryptographic Failures

**Description**: Failures related to cryptography (or lack thereof), leading to exposure of sensitive data.

**Common Vulnerabilities**:
- Transmitting data in cleartext (HTTP instead of HTTPS)
- Using weak cryptographic algorithms (MD5, SHA1, DES)
- Hardcoded encryption keys
- No encryption of sensitive data at rest
- Improper certificate validation

```python
# ✅ SECURE: Data encryption at rest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64
import os

class DataEncryption:
    """Encrypt sensitive data at rest"""

    def __init__(self):
        # Load encryption key from environment/Vault
        self.key = os.getenv('ENCRYPTION_KEY')
        if not self.key:
            raise ValueError("ENCRYPTION_KEY not set")

        self.cipher = Fernet(self.key.encode())

    def encrypt(self, plaintext: str) -> str:
        """Encrypt string data"""
        encrypted = self.cipher.encrypt(plaintext.encode())
        return base64.urlsafe_b64encode(encrypted).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt string data"""
        decoded = base64.urlsafe_b64decode(ciphertext.encode())
        decrypted = self.cipher.decrypt(decoded)
        return decrypted.decode()

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# ✅ SECURE: TLS/SSL enforcement
from flask_talisman import Talisman

app = Flask(__name__)

# Force HTTPS
Talisman(app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    strict_transport_security_preload=True
)

# ❌ NEVER DO THIS
import hashlib
def bad_encryption(data):
    return hashlib.md5(data.encode()).hexdigest()  # NOT ENCRYPTION!

def bad_key_storage():
    ENCRYPTION_KEY = "hardcoded-key-123"  # NEVER HARDCODE KEYS!
```

---

## A03:2025 - Injection

**Description**: User-supplied data is not validated, filtered, or sanitized, allowing attackers to inject malicious code.

**Types**: SQL Injection, NoSQL Injection, OS Command Injection, LDAP Injection, XPath Injection

```python
# ✅ SECURE: Command Injection Prevention
import subprocess
import shlex
from typing import List

def execute_command_vulnerable(filename):
    """❌ VULNERABLE: Command injection"""
    os.system(f"cat {filename}")  # Vulnerable to: "; rm -rf /"

def execute_command_secure(filename: str):
    """✅ SECURE: No shell, parameterized command"""
    # Validate filename
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        raise ValueError("Invalid filename")

    # Use subprocess without shell
    result = subprocess.run(
        ['cat', filename],  # List, not string
        capture_output=True,
        text=True,
        timeout=5,
        check=False
    )
    return result.stdout

# ✅ SECURE: NoSQL Injection Prevention (MongoDB)
from bson.objectid import ObjectId

def find_user_vulnerable(username):
    """❌ VULNERABLE: NoSQL injection"""
    user = db.users.find_one({'username': username})
    # Attacker can send: {"$ne": null} to bypass

def find_user_secure(username: str):
    """✅ SECURE: Type validation"""
    # Ensure username is a string
    if not isinstance(username, str):
        raise ValueError("Username must be a string")

    # Validate format
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        raise ValueError("Invalid username format")

    user = db.users.find_one({'username': username})
    return user

def find_by_id_secure(user_id: str):
    """✅ SECURE: Validate ObjectId"""
    if not ObjectId.is_valid(user_id):
        raise ValueError("Invalid user ID")

    user = db.users.find_one({'_id': ObjectId(user_id)})
    return user
```

---

## A04:2025 - Insecure Design

**Description**: Missing or ineffective security controls due to flawed design and threat modeling.

**Focus**: Shift-left security, threat modeling, secure design patterns

```python
# ✅ SECURE: Rate limiting to prevent abuse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379"
)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # Prevent brute force
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    user = authenticate(username, password)
    if user:
        return jsonify({'token': create_token(user)})
    else:
        # Don't reveal if username exists
        return jsonify({'error': 'Invalid credentials'}), 401

# ✅ SECURE: Account lockout mechanism
from datetime import datetime, timedelta

class AccountLockout:
    """Prevent brute force with account lockout"""

    def __init__(self, max_attempts: int = 5, lockout_duration: int = 900):
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration  # 15 minutes

    def record_failed_login(self, username: str):
        """Record failed login attempt"""
        key = f"login_attempts:{username}"
        attempts = cache.get(key) or 0
        attempts += 1

        cache.set(key, attempts, timeout=self.lockout_duration)

        if attempts >= self.max_attempts:
            self.lock_account(username)

    def lock_account(self, username: str):
        """Lock account for lockout duration"""
        key = f"account_locked:{username}"
        cache.set(key, True, timeout=self.lockout_duration)

    def is_locked(self, username: str) -> bool:
        """Check if account is locked"""
        return cache.get(f"account_locked:{username}") is not None

    def clear_attempts(self, username: str):
        """Clear failed attempts on successful login"""
        cache.delete(f"login_attempts:{username}")

# ✅ SECURE: CAPTCHA after failed attempts
@app.route('/api/login', methods=['POST'])
def login_with_captcha():
    username = request.json.get('username')
    password = request.json.get('password')

    lockout = AccountLockout()

    # Check if account is locked
    if lockout.is_locked(username):
        return jsonify({'error': 'Account locked. Try again later.'}), 429

    # Require CAPTCHA after 3 failed attempts
    attempts = cache.get(f"login_attempts:{username}") or 0
    if attempts >= 3:
        captcha_token = request.json.get('captcha_token')
        if not verify_captcha(captcha_token):
            return jsonify({'error': 'Invalid CAPTCHA'}), 400

    user = authenticate(username, password)
    if user:
        lockout.clear_attempts(username)
        return jsonify({'token': create_token(user)})
    else:
        lockout.record_failed_login(username)
        return jsonify({'error': 'Invalid credentials'}), 401
```

---

## A05:2025 - Security Misconfiguration

**Description**: Missing security hardening, unnecessary features enabled, default credentials, verbose errors.

```python
# ✅ SECURE: Production configuration
class ProductionConfig:
    """Secure production configuration"""

    # Flask settings
    DEBUG = False  # NEVER True in production
    TESTING = False
    SECRET_KEY = os.getenv('SECRET_KEY')  # From environment

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False  # No SQL logging in production

    # Session security
    SESSION_COOKIE_SECURE = True  # HTTPS only
    SESSION_COOKIE_HTTPONLY = True  # No JavaScript access
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)

    # CSRF protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None

    # Logging
    LOG_LEVEL = 'WARNING'
    LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'

    # File upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max
    UPLOAD_EXTENSIONS = ['.jpg', '.png', '.pdf']

    # CORS
    CORS_ORIGINS = ['https://app.example.com']

# ✅ SECURE: Error handling (no info disclosure)
@app.errorhandler(Exception)
def handle_exception(e):
    """Global exception handler"""

    # Log full error (not sent to client)
    app.logger.error(f"Unhandled exception: {str(e)}", exc_info=True)

    # Send generic error to client
    if isinstance(e, HTTPException):
        return jsonify({'error': e.description}), e.code
    else:
        return jsonify({'error': 'Internal server error'}), 500

# ❌ NEVER DO THIS
DEBUG = True  # In production!
app.run(host='0.0.0.0', debug=True)  # Debug mode exposed!
```

---

## A06:2025 - Vulnerable and Outdated Components

**Description**: Using components with known vulnerabilities, outdated libraries, or unmaintained dependencies.

```yaml
# ✅ SECURE: Dependabot configuration
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
    # Auto-merge security updates
    allow:
      - dependency-type: "all"
    # Version constraints
    ignore:
      - dependency-name: "django"
        versions: ["< 4.0"]  # Only update within major version

  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
```

```bash
# ✅ SECURE: Regular dependency audits
# Run in CI/CD pipeline

# Python
pip-audit --desc  # Check for known vulnerabilities
safety check     # Alternative tool

# Node.js
npm audit --audit-level=moderate
npm audit fix    # Auto-fix vulnerabilities

# Check for outdated packages
pip list --outdated
npm outdated
```

---

## A07:2025 - Identification and Authentication Failures

**Description**: Broken authentication mechanisms allowing attackers to compromise passwords, keys, or session tokens.

```python
# ✅ SECURE: Multi-Factor Authentication (MFA)
import pyotp
import qrcode
from io import BytesIO
import base64

class MFAManager:
    """Time-based One-Time Password (TOTP) implementation"""

    def generate_secret(self) -> str:
        """Generate TOTP secret for user"""
        return pyotp.random_base32()

    def get_provisioning_uri(self, username: str, secret: str) -> str:
        """Generate provisioning URI for QR code"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=username,
            issuer_name='MyApp'
        )

    def generate_qr_code(self, provisioning_uri: str) -> str:
        """Generate QR code image as base64"""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')

        return base64.b64encode(buffer.getvalue()).decode()

    def verify_totp(self, secret: str, token: str) -> bool:
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)  # Allow 30s window

# ✅ SECURE: MFA enrollment and verification
@app.route('/api/mfa/enroll', methods=['POST'])
@require_auth()
def enroll_mfa():
    user_id = request.current_user['sub']
    user = User.query.get(user_id)

    mfa = MFAManager()

    # Generate secret
    secret = mfa.generate_secret()

    # Store encrypted secret
    user.mfa_secret = encrypt_secret(secret)
    db.session.commit()

    # Generate QR code
    provisioning_uri = mfa.get_provisioning_uri(user.email, secret)
    qr_code = mfa.generate_qr_code(provisioning_uri)

    return jsonify({
        'secret': secret,  # Show once for manual entry
        'qr_code': qr_code
    })

@app.route('/api/mfa/verify', methods=['POST'])
@require_auth()
def verify_mfa():
    user_id = request.current_user['sub']
    user = User.query.get(user_id)
    token = request.json.get('token')

    mfa = MFAManager()
    secret = decrypt_secret(user.mfa_secret)

    if mfa.verify_totp(secret, token):
        user.mfa_enabled = True
        db.session.commit()
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Invalid MFA token'}), 401
```

---

## A08:2025 - Software and Data Integrity Failures

**Description**: Code/infrastructure that doesn't protect against integrity violations (unsigned updates, insecure CI/CD).

```yaml
# ✅ SECURE: Signed commits and releases
# .github/workflows/release.yml
name: Secure Release

on:
  push:
    tags:
      - 'v*'

jobs:
  verify-signature:
    name: Verify Commit Signature
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Verify GPG signature
        run: |
          git verify-commit HEAD || exit 1

  build-and-sign:
    name: Build and Sign Artifacts
    needs: verify-signature
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build application
        run: |
          python setup.py sdist bdist_wheel

      - name: Sign artifacts
        run: |
          gpg --armor --detach-sign dist/*.whl
          gpg --armor --detach-sign dist/*.tar.gz

      - name: Generate checksums
        run: |
          cd dist
          sha256sum * > SHA256SUMS
          gpg --armor --detach-sign SHA256SUMS

      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: signed-artifacts
          path: dist/
```

```python
# ✅ SECURE: Subresource Integrity (SRI) for CDN resources
# Use SRI hashes for external scripts/styles
integrity_hashes = {
    'bootstrap.min.css': 'sha384-9ndCyUa...',
    'jquery.min.js': 'sha384-KJ3o2D...'
}

# In templates
"""
<link rel="stylesheet"
      href="https://cdn.example.com/bootstrap.min.css"
      integrity="{{ integrity_hashes['bootstrap.min.css'] }}"
      crossorigin="anonymous">
"""
```

---

## A09:2025 - Security Logging and Monitoring Failures

**Description**: Insufficient logging and monitoring, preventing or delaying attack detection.

```python
# ✅ SECURE: Comprehensive security logging
import logging
import json
from datetime import datetime
from flask import request, g

class SecurityLogger:
    """Structured security event logging"""

    def __init__(self):
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)

        # JSON formatter for structured logs
        handler = logging.StreamHandler()
        handler.setFormatter(self._get_json_formatter())
        self.logger.addHandler(handler)

    def _get_json_formatter(self):
        """JSON log formatter"""
        class JsonFormatter(logging.Formatter):
            def format(self, record):
                log_data = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'level': record.levelname,
                    'message': record.getMessage(),
                    'logger': record.name
                }
                if hasattr(record, 'extra'):
                    log_data.update(record.extra)
                return json.dumps(log_data)

        return JsonFormatter()

    def log_auth_success(self, user_id: str, username: str):
        """Log successful authentication"""
        self.logger.info('Authentication successful', extra={
            'event_type': 'auth_success',
            'user_id': user_id,
            'username': username,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        })

    def log_auth_failure(self, username: str, reason: str):
        """Log failed authentication attempt"""
        self.logger.warning('Authentication failed', extra={
            'event_type': 'auth_failure',
            'username': username,
            'reason': reason,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        })

    def log_authorization_failure(self, user_id: str, resource: str, action: str):
        """Log authorization failure"""
        self.logger.warning('Authorization denied', extra={
            'event_type': 'authz_failure',
            'user_id': user_id,
            'resource': resource,
            'action': action,
            'ip_address': request.remote_addr
        })

    def log_sensitive_data_access(self, user_id: str, data_type: str, record_id: str):
        """Log access to sensitive data"""
        self.logger.info('Sensitive data accessed', extra={
            'event_type': 'data_access',
            'user_id': user_id,
            'data_type': data_type,
            'record_id': record_id,
            'ip_address': request.remote_addr
        })

    def log_security_event(self, event_type: str, severity: str, details: dict):
        """Log generic security event"""
        log_func = getattr(self.logger, severity.lower())
        log_func(f'Security event: {event_type}', extra={
            'event_type': event_type,
            'severity': severity,
            **details
        })

# ✅ SECURE: Request logging middleware
@app.before_request
def log_request():
    """Log all requests"""
    g.start_time = datetime.utcnow()

    # Don't log sensitive data
    safe_data = {}
    if request.json:
        safe_data = {k: v for k, v in request.json.items()
                     if k not in ['password', 'token', 'secret']}

    app.logger.info('Request started', extra={
        'method': request.method,
        'path': request.path,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'data': safe_data
    })

@app.after_request
def log_response(response):
    """Log response"""
    duration = (datetime.utcnow() - g.start_time).total_seconds()

    app.logger.info('Request completed', extra={
        'method': request.method,
        'path': request.path,
        'status': response.status_code,
        'duration_ms': duration * 1000
    })

    return response
```

---

## A10:2025 - Server-Side Request Forgery (SSRF)

**Description**: Application fetches remote resources without validating user-supplied URLs, allowing attackers to access internal systems.

```python
# ❌ VULNERABLE: SSRF attack
import requests

@app.route('/api/fetch-url', methods=['POST'])
def fetch_url_vulnerable():
    url = request.json.get('url')
    response = requests.get(url)  # Attacker can access internal services!
    return response.text

# ✅ SECURE: SSRF prevention
import ipaddress
from urllib.parse import urlparse

class SSRFProtection:
    """Prevent SSRF attacks"""

    # Blocked IP ranges
    BLOCKED_RANGES = [
        ipaddress.ip_network('127.0.0.0/8'),     # Loopback
        ipaddress.ip_network('10.0.0.0/8'),      # Private
        ipaddress.ip_network('172.16.0.0/12'),   # Private
        ipaddress.ip_network('192.168.0.0/16'),  # Private
        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
        ipaddress.ip_network('::1/128'),         # IPv6 loopback
        ipaddress.ip_network('fc00::/7'),        # IPv6 private
    ]

    # Allowed schemes
    ALLOWED_SCHEMES = ['http', 'https']

    # Allowed domains (whitelist approach)
    ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

    @classmethod
    def is_safe_url(cls, url: str) -> bool:
        """Validate URL for SSRF protection"""
        try:
            parsed = urlparse(url)

            # Check scheme
            if parsed.scheme not in cls.ALLOWED_SCHEMES:
                return False

            # Check domain whitelist
            if parsed.netloc not in cls.ALLOWED_DOMAINS:
                return False

            # Resolve hostname to IP
            import socket
            ip = socket.gethostbyname(parsed.netloc)
            ip_obj = ipaddress.ip_address(ip)

            # Check if IP is in blocked range
            for blocked_range in cls.BLOCKED_RANGES:
                if ip_obj in blocked_range:
                    return False

            return True

        except Exception:
            return False

@app.route('/api/fetch-url', methods=['POST'])
@require_auth()
def fetch_url_secure():
    url = request.json.get('url')

    # Validate URL
    if not SSRFProtection.is_safe_url(url):
        return jsonify({'error': 'URL not allowed'}), 400

    try:
        # Fetch with timeout and size limit
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False,  # Prevent redirect to internal
            stream=True
        )

        # Check content length
        content_length = response.headers.get('Content-Length')
        if content_length and int(content_length) > 10 * 1024 * 1024:  # 10MB
            return jsonify({'error': 'Response too large'}), 400

        # Read with limit
        content = response.raw.read(10 * 1024 * 1024)

        return jsonify({
            'status': response.status_code,
            'content': content.decode('utf-8')
        })

    except requests.RequestException as e:
        app.logger.error(f"Error fetching URL: {str(e)}")
        return jsonify({'error': 'Failed to fetch URL'}), 500
```
