# Windows UI Automation - Advanced Patterns

## Pattern: Secure Automation Session

```python
from contextlib import contextmanager
import uuid

class SecureAutomationSession:
    """Managed automation session with full security controls."""

    def __init__(self, permission_tier: str = 'read-only'):
        self.session_id = str(uuid.uuid4())
        self.permission_tier = permission_tier
        self.uia = None
        self.audit_logger = UIAuditLogger()
        self.timeout_manager = TimeoutManager()
        self.guard = AutomationGuard()

    @contextmanager
    def session(self):
        """Context manager for safe automation session."""
        try:
            self._initialize()
            yield self
        finally:
            self._cleanup()

    def _initialize(self):
        """Initialize automation with security checks."""
        self.uia = CreateObject('UIAutomationClient.CUIAutomation')
        self.audit_logger.log_session_start(self.session_id, self.permission_tier)

    def _cleanup(self):
        """Clean up automation session."""
        self.audit_logger.log_session_end(self.session_id)
        self.uia = None

    def find_and_interact(self, process: str, element_id: str, action: str, **kwargs):
        """Find element and perform action with full validation."""
        # Check limits
        self.guard.check_limits()

        # Validate process
        pid = get_process_pid(process)
        if not ProcessValidator().validate_process(pid):
            raise SecurityError(f"Process validation failed: {process}")

        # Find element with timeout
        with self.timeout_manager.timeout(30):
            element = self._find_element(process, element_id)

        # Perform action based on permission tier
        if action == 'get_value':
            return self._get_value(element)
        elif action == 'click':
            return self._click(element)
        elif action == 'send_keys':
            return self._send_keys(element, kwargs.get('keys', ''))

    def _find_element(self, process: str, element_id: str):
        """Find element with caching and validation."""
        root = self.uia.GetRootElement()
        # Implementation details...
        pass
```

## Pattern: Hierarchical Element Discovery

```python
class ElementDiscovery:
    """Safe hierarchical element discovery."""

    def find_element_path(self, path: list[str]) -> 'UIElement':
        """Find element by path with validation at each level."""
        current = self.uia.GetRootElement()

        for level, identifier in enumerate(path):
            # Validate identifier
            if not validate_element_identifier(identifier):
                raise ValidationError(f"Invalid identifier: {identifier}")

            # Find child element
            child = self._find_child(current, identifier)
            if not child:
                raise ElementNotFoundError(f"Element not found: {identifier}")

            # Validate we can access this element
            if not self._can_access(child):
                raise SecurityError(f"Access denied to element: {identifier}")

            current = child

        return current
```

## Pattern: Robust Wait Conditions

```python
class WaitConditions:
    """Wait for UI conditions with timeout and safety."""

    def wait_for_element(
        self,
        condition: callable,
        timeout: int = 30,
        poll_interval: float = 0.5
    ) -> 'UIElement':
        """Wait for element matching condition."""
        start = time.time()

        while time.time() - start < timeout:
            try:
                element = condition()
                if element:
                    return element
            except Exception:
                pass

            time.sleep(poll_interval)

        raise TimeoutError(f"Element not found within {timeout}s")

    def wait_for_window(self, title: str, timeout: int = 30):
        """Wait for window to appear."""
        return self.wait_for_element(
            lambda: self._find_window_by_title(title),
            timeout=timeout
        )

    def wait_for_element_state(self, element, state: str, timeout: int = 10):
        """Wait for element to reach state."""
        return self.wait_for_element(
            lambda: element if element.get_state() == state else None,
            timeout=timeout
        )
```

## Pattern: Multi-Monitor Support

```python
class MultiMonitorAutomation:
    """Handle automation across multiple monitors."""

    def get_element_monitor(self, element) -> int:
        """Determine which monitor contains element."""
        rect = element.bounding_rectangle
        monitors = self._enumerate_monitors()

        for idx, monitor in enumerate(monitors):
            if self._rect_in_monitor(rect, monitor):
                return idx

        return 0  # Primary monitor fallback

    def ensure_visible(self, element):
        """Ensure element is visible on screen."""
        rect = element.bounding_rectangle
        monitor = self.get_element_monitor(element)

        if not self._is_fully_visible(rect, monitor):
            element.scroll_into_view()
```

## Pattern: Clipboard Security

```python
class SecureClipboard:
    """Secure clipboard operations for automation."""

    def copy_to_clipboard(self, text: str, clear_after: int = 30):
        """Copy text with automatic clearing."""
        # Set clipboard
        ctypes.windll.user32.OpenClipboard(0)
        ctypes.windll.user32.EmptyClipboard()
        # ... set text ...
        ctypes.windll.user32.CloseClipboard()

        # Schedule clearing
        threading.Timer(clear_after, self._clear_clipboard).start()

    def _clear_clipboard(self):
        """Clear clipboard contents."""
        ctypes.windll.user32.OpenClipboard(0)
        ctypes.windll.user32.EmptyClipboard()
        ctypes.windll.user32.CloseClipboard()
```

## Pattern: Screenshot Redaction

```python
class SecureScreenCapture:
    """Screenshot capture with sensitive content redaction."""

    def capture_with_redaction(self, hwnd: int) -> bytes:
        """Capture window with sensitive areas redacted."""
        # Capture screenshot
        image = self._capture_window(hwnd)

        # Find sensitive elements
        sensitive_rects = self._find_sensitive_regions(hwnd)

        # Redact sensitive areas
        for rect in sensitive_rects:
            image = self._redact_region(image, rect)

        return image

    def _find_sensitive_regions(self, hwnd: int) -> list:
        """Find regions containing sensitive content."""
        regions = []
        elements = self._enumerate_elements(hwnd)

        for element in elements:
            if is_credential_element(element.name):
                regions.append(element.bounding_rectangle)

        return regions
```
