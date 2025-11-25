# D-Bus - Advanced Patterns

## Pattern: Async D-Bus with GIO

```python
from gi.repository import Gio, GLib

class AsyncDBusClient:
    """Async D-Bus client using GIO."""

    def __init__(self, bus_type: str = 'session'):
        if bus_type == 'session':
            self.bus = Gio.bus_get_sync(Gio.BusType.SESSION)
        else:
            self.bus = Gio.bus_get_sync(Gio.BusType.SYSTEM)

    def call_method_async(
        self,
        bus_name: str,
        object_path: str,
        interface: str,
        method: str,
        parameters: GLib.Variant,
        callback
    ):
        """Call method asynchronously."""
        self.bus.call(
            bus_name,
            object_path,
            interface,
            method,
            parameters,
            None,
            Gio.DBusCallFlags.NONE,
            30000,  # timeout ms
            None,
            callback
        )
```

## Pattern: Connection Pooling

```python
class DBusConnectionPool:
    """Pool D-Bus connections for reuse."""

    def __init__(self, max_connections: int = 5):
        self.max_connections = max_connections
        self.connections = []
        self.lock = threading.Lock()

    def get_connection(self):
        """Get connection from pool."""
        with self.lock:
            if self.connections:
                return self.connections.pop()
            return dbus.SessionBus()

    def return_connection(self, conn):
        """Return connection to pool."""
        with self.lock:
            if len(self.connections) < self.max_connections:
                self.connections.append(conn)
```

## Pattern: Service Wrapper

```python
class NotificationService:
    """Type-safe wrapper for Notifications service."""

    BUS_NAME = 'org.freedesktop.Notifications'
    OBJECT_PATH = '/org/freedesktop/Notifications'
    INTERFACE = 'org.freedesktop.Notifications'

    def __init__(self, client: SecureDBusClient):
        self.client = client

    def notify(
        self,
        summary: str,
        body: str = '',
        icon: str = '',
        timeout: int = 5000
    ) -> int:
        """Send notification."""
        return self.client.call_method(
            self.BUS_NAME,
            self.OBJECT_PATH,
            self.INTERFACE,
            'Notify',
            '',          # app_name
            0,           # replaces_id
            icon,
            summary,
            body,
            [],          # actions
            {},          # hints
            timeout
        )

    def close(self, notification_id: int):
        """Close notification."""
        return self.client.call_method(
            self.BUS_NAME,
            self.OBJECT_PATH,
            self.INTERFACE,
            'CloseNotification',
            notification_id
        )
```

## Pattern: Retry Logic

```python
import time

class RetryableDBusCall:
    """Retry D-Bus calls on transient failures."""

    RETRYABLE_ERRORS = [
        'org.freedesktop.DBus.Error.ServiceUnknown',
        'org.freedesktop.DBus.Error.NoReply',
    ]

    def __init__(self, max_retries: int = 3):
        self.max_retries = max_retries

    def call(self, method, *args, **kwargs):
        """Call with retry on transient errors."""
        for attempt in range(self.max_retries):
            try:
                return method(*args, **kwargs)
            except DBusException as e:
                if e.get_dbus_name() not in self.RETRYABLE_ERRORS:
                    raise
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(2 ** attempt)
```

## Pattern: Interface Caching

```python
class CachedInterfaceProxy:
    """Cache D-Bus interface proxies."""

    def __init__(self, client: SecureDBusClient):
        self.client = client
        self.cache = {}

    def get_interface(self, bus_name: str, object_path: str, interface: str):
        """Get cached interface proxy."""
        key = (bus_name, object_path, interface)

        if key not in self.cache:
            proxy = self.client.get_object(bus_name, object_path)
            self.cache[key] = dbus.Interface(proxy, interface)

        return self.cache[key]

    def invalidate(self, bus_name: str = None):
        """Invalidate cache."""
        if bus_name:
            keys = [k for k in self.cache if k[0] == bus_name]
            for key in keys:
                del self.cache[key]
        else:
            self.cache.clear()
```
