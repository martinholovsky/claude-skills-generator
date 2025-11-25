# AppleScript - Security Examples

## Command Injection Prevention

```applescript
-- BAD: Vulnerable to command injection
set fileName to user_input
do shell script "cat " & fileName

-- GOOD: Safe with quoted form
set fileName to user_input
do shell script "cat " & quoted form of fileName
```

## Safe String Building

```python
def build_safe_script(template: str, params: dict) -> str:
    """Build AppleScript with safe parameter substitution."""
    for key, value in params.items():
        # Escape special characters
        safe_value = value.replace('\\', '\\\\').replace('"', '\\"')
        template = template.replace(f'{{{key}}}', safe_value)
    return template

# Usage
template = 'tell application "{app}" to activate'
script = build_safe_script(template, {'app': 'Finder'})
```

## Blocked Pattern Detection

```python
DANGEROUS_PATTERNS = [
    r'do shell script.*with administrator',
    r'sudo',
    r'rm\s+-rf',
    r'>\s*/etc/',
    r'curl.*\|.*sh',
    r'eval\s*\(',
]

def check_dangerous_patterns(script: str) -> list[str]:
    """Find dangerous patterns in script."""
    found = []
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, script, re.IGNORECASE):
            found.append(pattern)
    return found
```

## Audit Logging

```python
import json
import hashlib

def log_script_execution(script: str, result: str, success: bool):
    """Log AppleScript execution for audit."""
    record = {
        'timestamp': datetime.utcnow().isoformat(),
        'event': 'applescript_execution',
        'script_hash': hashlib.sha256(script.encode()).hexdigest(),
        'script_preview': script[:100],
        'success': success,
        'result_length': len(result)
    }
    logging.getLogger('applescript.audit').info(json.dumps(record))
```

## Input Validation

```python
def validate_app_name(name: str) -> bool:
    """Validate application name is safe."""
    # Only allow alphanumeric, spaces, hyphens
    return bool(re.match(r'^[a-zA-Z0-9 \-]+$', name))

def validate_file_path(path: str) -> bool:
    """Validate file path is safe."""
    # No path traversal
    if '..' in path:
        return False
    # Must be absolute
    if not path.startswith('/'):
        return False
    # Canonicalize and check
    return os.path.realpath(path) == path
```

## Shell Command Allowlist

```python
ALLOWED_SHELL_COMMANDS = {
    'echo': {'max_args': 10},
    'date': {'max_args': 5},
    'pwd': {'max_args': 0},
    'ls': {'max_args': 5, 'blocked_flags': ['-R']},
    'cat': {'max_args': 1},
}

def validate_shell_command(command: str) -> bool:
    """Validate shell command against allowlist."""
    parts = shlex.split(command)
    cmd = parts[0]
    args = parts[1:]

    if cmd not in ALLOWED_SHELL_COMMANDS:
        return False

    config = ALLOWED_SHELL_COMMANDS[cmd]
    if len(args) > config.get('max_args', 0):
        return False

    blocked = config.get('blocked_flags', [])
    if any(arg in blocked for arg in args):
        return False

    return True
```
