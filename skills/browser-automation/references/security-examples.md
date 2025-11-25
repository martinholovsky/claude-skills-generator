# Browser Automation - Security Examples

## Domain Validation

```python
from urllib.parse import urlparse

def validate_domain(url: str, allowlist: list, blocklist: list) -> bool:
    """Comprehensive domain validation."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower().lstrip('www.')

    # Check blocklist first
    for blocked in blocklist:
        if domain == blocked or domain.endswith('.' + blocked):
            return False

    # Check allowlist
    if allowlist:
        for allowed in allowlist:
            if domain == allowed or domain.endswith('.' + allowed):
                return True
        return False

    return True
```

## Credential Pattern Detection

```python
import re

CREDENTIAL_PATTERNS = [
    (r'^[A-Za-z0-9+/]{40,}={0,2}$', 'base64_token'),
    (r'^ghp_[A-Za-z0-9]{36}$', 'github_pat'),
    (r'^sk-[A-Za-z0-9]{48}$', 'openai_key'),
    (r'^AKIA[A-Z0-9]{16}$', 'aws_access_key'),
    (r'^[0-9]{13,16}$', 'credit_card'),
    (r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$', 'strong_password'),
]

def detect_credential(value: str) -> str | None:
    """Detect if value looks like a credential."""
    for pattern, cred_type in CREDENTIAL_PATTERNS:
        if re.match(pattern, value):
            return cred_type
    return None
```

## Audit Logging

```python
import json
import logging

class BrowserAuditLogger:
    """Comprehensive browser automation audit logging."""

    def __init__(self):
        self.logger = logging.getLogger('browser.audit')

    def log_navigation(self, url: str, success: bool):
        record = {
            'timestamp': datetime.utcnow().isoformat(),
            'event': 'navigation',
            'url': self._sanitize_url(url),
            'success': success
        }
        self.logger.info(json.dumps(record))

    def log_interaction(self, action: str, selector: str, element_type: str):
        record = {
            'timestamp': datetime.utcnow().isoformat(),
            'event': 'interaction',
            'action': action,
            'selector': selector,
            'element_type': element_type
        }
        self.logger.info(json.dumps(record))

    def log_blocked(self, reason: str, url: str = None, selector: str = None):
        record = {
            'timestamp': datetime.utcnow().isoformat(),
            'event': 'blocked',
            'reason': reason,
            'url': self._sanitize_url(url) if url else None,
            'selector': selector
        }
        self.logger.warning(json.dumps(record))

    def _sanitize_url(self, url: str) -> str:
        """Remove credentials from URL."""
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        # Remove username:password
        sanitized = parsed._replace(netloc=parsed.hostname or '')
        return urlunparse(sanitized)
```

## Cookie Security

```python
class CookieManager:
    """Secure cookie management."""

    SENSITIVE_COOKIE_PATTERNS = [
        'session', 'token', 'auth', 'sid', 'jwt'
    ]

    def __init__(self, context):
        self.context = context

    def get_cookies_filtered(self) -> list:
        """Get cookies with sensitive ones filtered."""
        cookies = self.context.cookies()
        filtered = []

        for cookie in cookies:
            name = cookie['name'].lower()
            if any(p in name for p in self.SENSITIVE_COOKIE_PATTERNS):
                cookie['value'] = '[REDACTED]'
            filtered.append(cookie)

        return filtered

    def clear_sensitive(self):
        """Clear only sensitive cookies."""
        cookies = self.context.cookies()
        to_clear = []

        for cookie in cookies:
            name = cookie['name'].lower()
            if any(p in name for p in self.SENSITIVE_COOKIE_PATTERNS):
                to_clear.append(cookie)

        for cookie in to_clear:
            self.context.clear_cookies(name=cookie['name'])
```

## Request Filtering

```python
class RequestFilter:
    """Filter and log network requests."""

    BLOCKED_DOMAINS = [
        'google-analytics.com',
        'googletagmanager.com',
        'facebook.com',
        'doubleclick.net',
    ]

    def should_block(self, url: str) -> bool:
        """Determine if request should be blocked."""
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lower()

        for blocked in self.BLOCKED_DOMAINS:
            if domain == blocked or domain.endswith('.' + blocked):
                return True

        return False

    def sanitize_headers(self, headers: dict) -> dict:
        """Remove sensitive headers."""
        sensitive = ['authorization', 'cookie', 'x-api-key']
        return {
            k: '[REDACTED]' if k.lower() in sensitive else v
            for k, v in headers.items()
        }
```
