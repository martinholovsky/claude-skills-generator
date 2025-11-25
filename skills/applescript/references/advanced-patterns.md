# AppleScript - Advanced Patterns

## Pattern: Subprocess Runner with Timeout

```python
import subprocess
import signal

class AppleScriptRunner:
    """Execute AppleScript with process management."""

    def execute_with_timeout(self, script: str, timeout: int = 30) -> str:
        """Execute script with enforced timeout."""
        process = subprocess.Popen(
            ['osascript', '-e', script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        try:
            stdout, stderr = process.communicate(timeout=timeout)
            if process.returncode != 0:
                raise AppleScriptError(stderr.decode())
            return stdout.decode().strip()
        except subprocess.TimeoutExpired:
            process.kill()
            raise TimeoutError(f"Script timed out after {timeout}s")
```

## Pattern: Script Template Engine

```python
class ScriptTemplates:
    """Predefined safe script templates."""

    TEMPLATES = {
        'activate_app': '''
tell application "{app}"
    activate
end tell
''',
        'get_selection': '''
tell application "Finder"
    return selection as alias list
end tell
''',
        'display_dialog': '''
display dialog "{message}" buttons {{"OK"}} default button 1
''',
    }

    def render(self, template_name: str, params: dict) -> str:
        """Render template with validated parameters."""
        if template_name not in self.TEMPLATES:
            raise ValueError(f"Unknown template: {template_name}")

        template = self.TEMPLATES[template_name]

        # Validate and escape all parameters
        for key, value in params.items():
            if not self._validate_param(key, value):
                raise ValueError(f"Invalid parameter: {key}")
            escaped = value.replace('\\', '\\\\').replace('"', '\\"')
            template = template.replace(f'{{{key}}}', escaped)

        return template.strip()
```

## Pattern: JXA Modern Wrapper

```javascript
// Modern JXA wrapper with security
function secureAutomation(appName, operations) {
    const BLOCKED = ['Terminal', 'Keychain Access'];
    if (BLOCKED.includes(appName)) {
        throw new Error(`Blocked: ${appName}`);
    }

    const app = Application(appName);
    const results = [];

    for (const op of operations) {
        if (typeof app[op.method] !== 'function') {
            throw new Error(`Invalid method: ${op.method}`);
        }
        results.push(app[op.method](...(op.args || [])));
    }

    return results;
}
```

## Pattern: Async Execution

```python
import asyncio

class AsyncAppleScriptRunner:
    """Async AppleScript execution."""

    async def execute_async(self, script: str, timeout: int = 30) -> str:
        """Execute script asynchronously."""
        process = await asyncio.create_subprocess_exec(
            'osascript', '-e', script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            return stdout.decode().strip()
        except asyncio.TimeoutError:
            process.kill()
            raise

    async def execute_batch(self, scripts: list[str]) -> list[str]:
        """Execute multiple scripts concurrently."""
        tasks = [self.execute_async(s) for s in scripts]
        return await asyncio.gather(*tasks, return_exceptions=True)
```

## Pattern: Result Parsing

```python
class AppleScriptResultParser:
    """Parse AppleScript return values."""

    @staticmethod
    def parse_list(result: str) -> list:
        """Parse AppleScript list to Python list."""
        # Handle {item1, item2, item3}
        result = result.strip()
        if result.startswith('{') and result.endswith('}'):
            result = result[1:-1]
        return [item.strip().strip('"') for item in result.split(',')]

    @staticmethod
    def parse_record(result: str) -> dict:
        """Parse AppleScript record to Python dict."""
        # Handle {key:value, key:value}
        record = {}
        result = result.strip()[1:-1]
        for pair in result.split(','):
            key, value = pair.split(':')
            record[key.strip()] = value.strip().strip('"')
        return record
```
