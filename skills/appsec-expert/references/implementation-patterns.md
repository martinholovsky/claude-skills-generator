# Advanced Implementation Patterns

This file contains advanced security patterns referenced from main SKILL.md Section 4.

---

## Pattern 6: Security Headers Implementation

```python
# ✅ SECURE: Comprehensive security headers
from flask import Flask, Response
import secrets

app = Flask(__name__)

@app.after_request
def set_security_headers(response: Response) -> Response:
    """Apply security headers to all responses"""

    # Generate nonce for CSP
    nonce = secrets.token_urlsafe(16)
    response.headers['X-CSP-Nonce'] = nonce

    # Content Security Policy (CSP)
    csp_directives = [
        "default-src 'self'",
        f"script-src 'self' 'nonce-{nonce}'",
        "style-src 'self' 'unsafe-inline'",  # Consider nonce for styles too
        "img-src 'self' data: https:",
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",  # Prevent clickjacking
        "base-uri 'self'",
        "form-action 'self'",
        "upgrade-insecure-requests"  # Upgrade HTTP to HTTPS
    ]
    response.headers['Content-Security-Policy'] = '; '.join(csp_directives)

    # HTTP Strict Transport Security (HSTS)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Clickjacking protection
    response.headers['X-Frame-Options'] = 'DENY'

    # XSS protection (legacy, but doesn't hurt)
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Permissions policy (formerly Feature-Policy)
    permissions = [
        "geolocation=()",
        "microphone=()",
        "camera=()",
        "payment=()",
        "usb=()",
        "magnetometer=()",
        "gyroscope=()",
        "accelerometer=()"
    ]
    response.headers['Permissions-Policy'] = ', '.join(permissions)

    # Cross-Origin policies
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'

    return response

# ✅ SECURE: CORS configuration
from flask_cors import CORS

CORS(app, resources={
    r"/api/*": {
        "origins": ["https://app.example.com"],  # Specific origins only
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["X-Total-Count"],
        "supports_credentials": True,
        "max_age": 3600
    }
})
```

---

## Pattern 7: Secrets Management with HashiCorp Vault

```python
# ✅ SECURE: HashiCorp Vault integration
import hvac
import os
from typing import Dict, Optional
from functools import lru_cache

class VaultSecretsManager:
    """Secure secrets management with HashiCorp Vault"""

    def __init__(self):
        self.vault_url = os.getenv('VAULT_URL', 'http://localhost:8200')
        self.vault_token = os.getenv('VAULT_TOKEN')

        if not self.vault_token:
            # Use AppRole authentication in production
            self.vault_token = self._authenticate_approle()

        self.client = hvac.Client(url=self.vault_url, token=self.vault_token)

        if not self.client.is_authenticated():
            raise Exception("Vault authentication failed")

    def _authenticate_approle(self) -> str:
        """Authenticate using AppRole (production method)"""
        role_id = os.getenv('VAULT_ROLE_ID')
        secret_id = os.getenv('VAULT_SECRET_ID')

        client = hvac.Client(url=self.vault_url)
        response = client.auth.approle.login(
            role_id=role_id,
            secret_id=secret_id
        )
        return response['auth']['client_token']

    @lru_cache(maxsize=128)
    def get_secret(self, path: str, key: Optional[str] = None) -> Dict:
        """Get secret from Vault (cached)"""
        try:
            secret = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point='secret'
            )

            if key:
                return secret['data']['data'].get(key)

            return secret['data']['data']

        except Exception as e:
            raise Exception(f"Failed to retrieve secret from {path}: {str(e)}")

    def get_database_credentials(self, role: str) -> Dict:
        """Get dynamic database credentials"""
        response = self.client.secrets.database.generate_credentials(
            name=role,
            mount_point='database'
        )
        return {
            'username': response['data']['username'],
            'password': response['data']['password'],
            'ttl': response['lease_duration']
        }

    def rotate_secret(self, path: str, new_value: Dict):
        """Rotate secret in Vault"""
        self.client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret=new_value,
            mount_point='secret'
        )
        # Clear cache after rotation
        self.get_secret.cache_clear()

# ✅ SECURE: Environment-specific secrets
class Config:
    """Application configuration with Vault"""

    def __init__(self):
        self.vault = VaultSecretsManager()

        # Get secrets from Vault
        db_creds = self.vault.get_secret('myapp/database')
        api_keys = self.vault.get_secret('myapp/api-keys')

        self.DATABASE_URL = f"postgresql://{db_creds['username']}:{db_creds['password']}@{db_creds['host']}/{db_creds['database']}"
        self.SECRET_KEY = self.vault.get_secret('myapp/flask', 'secret_key')
        self.STRIPE_API_KEY = api_keys['stripe']
        self.SENDGRID_API_KEY = api_keys['sendgrid']

# ❌ NEVER DO THIS
# SECRET_KEY = 'hardcoded-secret-key'  # INSECURE!
# DATABASE_URL = 'postgresql://admin:password123@localhost/db'  # INSECURE!
```

---

## Pattern 8: SAST/DAST/SCA Integration in CI/CD

```yaml
# ✅ SECURE: GitHub Actions security pipeline
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  sast-semgrep:
    name: SAST - Semgrep
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Semgrep Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
            p/ci
            p/python
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: semgrep.sarif

  sast-sonarqube:
    name: SAST - SonarQube
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history for better analysis

      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}

      - name: SonarQube Quality Gate
        uses: sonarsource/sonarqube-quality-gate-action@master
        timeout-minutes: 5
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}

  sca-snyk:
    name: SCA - Snyk
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Snyk to check for vulnerabilities
        uses: snyk/actions/python@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high --fail-on=all

      - name: Upload Snyk results
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: snyk.sarif

  sca-dependabot:
    name: SCA - Dependency Review
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Dependency Review
        uses: actions/dependency-review-action@v3
        with:
          fail-on-severity: moderate

  secrets-scan:
    name: Secrets Scanning
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0

      - name: Gitleaks Scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: TruffleHog Scan
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD

  dast-zap:
    name: DAST - OWASP ZAP
    runs-on: ubuntu-latest
    needs: [sast-semgrep, sca-snyk]  # Run after SAST/SCA
    steps:
      - uses: actions/checkout@v3

      - name: Build and start application
        run: |
          docker-compose up -d
          sleep 30  # Wait for app to start

      - name: OWASP ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:8000'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'

      - name: Upload ZAP results
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: zap_results.sarif

  security-gate:
    name: Security Quality Gate
    runs-on: ubuntu-latest
    needs: [sast-semgrep, sast-sonarqube, sca-snyk, secrets-scan, dast-zap]
    if: always()
    steps:
      - name: Check security scan results
        run: |
          if [ "${{ needs.sast-semgrep.result }}" != "success" ] || \
             [ "${{ needs.sca-snyk.result }}" != "success" ] || \
             [ "${{ needs.secrets-scan.result }}" != "success" ]; then
            echo "Security scans failed!"
            exit 1
          fi
```
