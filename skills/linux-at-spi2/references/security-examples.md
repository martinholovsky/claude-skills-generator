# AT-SPI2 - Security Examples

## Role-Based Access Control

```python
BLOCKED_ROLES = {
    Atspi.Role.PASSWORD_TEXT: 'Password input',
    Atspi.Role.TERMINAL: 'Terminal emulator',
}

SENSITIVE_ROLES = {
    Atspi.Role.TEXT: ['password', 'secret', 'token', 'key'],
}

def check_role_access(obj: Atspi.Accessible) -> bool:
    """Validate access based on object role."""
    role = obj.get_role()

    if role in BLOCKED_ROLES:
        return False

    if role in SENSITIVE_ROLES:
        name = obj.get_name().lower()
        if any(word in name for word in SENSITIVE_ROLES[role]):
            return False

    return True
```

## D-Bus Credential Validation

```python
import dbus

def validate_dbus_peer(bus_name: str) -> dict:
    """Get D-Bus peer credentials."""
    bus = dbus.SessionBus()
    dbus_obj = bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
    dbus_iface = dbus.Interface(dbus_obj, 'org.freedesktop.DBus')

    pid = dbus_iface.GetConnectionUnixProcessID(bus_name)
    uid = dbus_iface.GetConnectionUnixUser(bus_name)

    return {'pid': pid, 'uid': uid, 'bus_name': bus_name}
```

## Audit Logging

```python
import json
import logging

class ATSPIAuditLogger:
    """Comprehensive audit logging."""

    def log_operation(self, operation: str, app: str, element: str, success: bool):
        record = {
            'timestamp': datetime.utcnow().isoformat(),
            'event': 'atspi_operation',
            'operation': operation,
            'application': app,
            'element': element,
            'success': success
        }
        logging.getLogger('atspi.audit').info(json.dumps(record))

    def log_blocked_access(self, reason: str, app: str, role: str):
        record = {
            'timestamp': datetime.utcnow().isoformat(),
            'event': 'atspi_blocked',
            'reason': reason,
            'application': app,
            'role': role
        }
        logging.getLogger('atspi.audit').warning(json.dumps(record))
```

## Rate Limiting

```python
import time
from collections import defaultdict

class ActionRateLimiter:
    """Rate limit AT-SPI2 actions."""

    def __init__(self, max_actions: int = 30, period: int = 60):
        self.max_actions = max_actions
        self.period = period
        self.actions = defaultdict(list)

    def check(self, app_name: str) -> bool:
        """Check if action is allowed."""
        now = time.time()
        cutoff = now - self.period

        # Clean old entries
        self.actions[app_name] = [
            t for t in self.actions[app_name] if t > cutoff
        ]

        # Check limit
        if len(self.actions[app_name]) >= self.max_actions:
            return False

        self.actions[app_name].append(now)
        return True
```

## Input Validation

```python
def validate_search_criteria(criteria: dict) -> bool:
    """Validate AT-SPI2 search criteria."""
    allowed_keys = {'name', 'role', 'state', 'description'}

    for key in criteria:
        if key not in allowed_keys:
            return False

    if 'name' in criteria:
        if len(criteria['name']) > 255:
            return False
        if not criteria['name'].isprintable():
            return False

    return True
```
