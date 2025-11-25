# WebSocket Security Examples Reference

## CSWSH Prevention Complete Example

```python
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from jose import jwt, JWTError
import logging

logger = logging.getLogger(__name__)

ALLOWED_ORIGINS = ["https://app.example.com"]
SECRET_KEY = os.environ["JWT_SECRET"]

class SecureWebSocketHandler:
    """Complete secure WebSocket implementation."""

    async def validate_origin(self, websocket: WebSocket) -> bool:
        origin = websocket.headers.get("origin")

        if not origin:
            logger.warning(f"No origin header from {websocket.client.host}")
            return False

        if origin not in ALLOWED_ORIGINS:
            logger.warning(f"Invalid origin {origin} from {websocket.client.host}")
            await websocket.close(code=4003, reason="Invalid origin")
            return False

        return True

    async def authenticate(self, websocket: WebSocket) -> User | None:
        token = websocket.query_params.get("token")

        if not token:
            await websocket.close(code=4001, reason="Token required")
            return None

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user = await user_service.get(payload["sub"])
            return user
        except JWTError as e:
            logger.warning(f"Invalid token: {e}")
            await websocket.close(code=4001, reason="Invalid token")
            return None

    async def handle(self, websocket: WebSocket):
        # 1. Validate origin
        if not await self.validate_origin(websocket):
            return

        # 2. Authenticate
        user = await self.authenticate(websocket)
        if not user:
            return

        # 3. Accept only after validation
        await websocket.accept()

        logger.info(f"WebSocket connected: user={user.id}, ip={websocket.client.host}")

        try:
            while True:
                data = await websocket.receive_json()
                await self.process_message(websocket, user, data)
        except WebSocketDisconnect:
            logger.info(f"WebSocket disconnected: user={user.id}")

    async def process_message(self, websocket, user, data):
        # Validate message format
        try:
            message = Message(**data)
        except ValueError as e:
            await websocket.send_json({"error": str(e)})
            return

        # Check permission
        if not user.has_permission(f"ws:{message.action}"):
            logger.warning(f"Permission denied: user={user.id}, action={message.action}")
            await websocket.send_json({"error": "Permission denied"})
            return

        # Process
        result = await self.handlers[message.action](user, message.data)
        await websocket.send_json(result)

handler = SecureWebSocketHandler()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await handler.handle(websocket)
```

---

## Browser-Side Token Authentication

```javascript
// Client-side: Pass token explicitly (not via cookies)
class SecureWebSocket {
    constructor(url, token) {
        this.url = url;
        this.token = token;
        this.ws = null;
    }

    connect() {
        // Pass token as query parameter
        const wsUrl = `${this.url}?token=${encodeURIComponent(this.token)}`;
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            console.log('Connected');
        };

        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);

            // Handle token rotation
            if (data.new_token) {
                this.token = data.new_token;
            }
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    send(action, data) {
        this.ws.send(JSON.stringify({ action, data }));
    }
}

// Usage
const token = await getAuthToken();  // From login
const ws = new SecureWebSocket('wss://api.example.com/ws', token);
ws.connect();
```

---

## Rate Limiting Implementation

```python
from collections import defaultdict
from time import time
import asyncio

class WebSocketRateLimiter:
    def __init__(self, max_per_minute: int = 60):
        self.max_per_minute = max_per_minute
        self.windows: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def check(self, user_id: str) -> bool:
        async with self._lock:
            now = time()
            window = self.windows[user_id]

            # Remove expired timestamps
            window[:] = [t for t in window if t > now - 60]

            if len(window) >= self.max_per_minute:
                return False

            window.append(now)
            return True

    async def reset(self, user_id: str):
        async with self._lock:
            self.windows.pop(user_id, None)

rate_limiter = WebSocketRateLimiter(max_per_minute=60)

# Usage in handler
if not await rate_limiter.check(user.id):
    await websocket.send_json({"error": "Rate limited", "retry_after": 60})
    continue
```

---

## Connection Manager with Security

```python
class SecureConnectionManager:
    def __init__(self):
        self.connections: dict[str, WebSocket] = {}
        self.user_to_socket: dict[str, str] = {}
        self.ip_counts: dict[str, int] = defaultdict(int)
        self.max_per_ip = 10
        self._lock = asyncio.Lock()

    async def connect(
        self,
        websocket: WebSocket,
        user_id: str,
        conn_id: str
    ) -> bool:
        ip = websocket.client.host

        async with self._lock:
            # Check IP limit
            if self.ip_counts[ip] >= self.max_per_ip:
                return False

            # Disconnect existing connection for user (single session)
            if user_id in self.user_to_socket:
                old_id = self.user_to_socket[user_id]
                await self.disconnect(old_id, user_id, ip)

            self.connections[conn_id] = websocket
            self.user_to_socket[user_id] = conn_id
            self.ip_counts[ip] += 1

        return True

    async def disconnect(self, conn_id: str, user_id: str, ip: str):
        async with self._lock:
            if conn_id in self.connections:
                try:
                    await self.connections[conn_id].close()
                except:
                    pass
                del self.connections[conn_id]

            self.user_to_socket.pop(user_id, None)
            self.ip_counts[ip] = max(0, self.ip_counts[ip] - 1)

    async def send_to_user(self, user_id: str, message: dict):
        conn_id = self.user_to_socket.get(user_id)
        if conn_id and conn_id in self.connections:
            await self.connections[conn_id].send_json(message)

    async def broadcast(self, message: dict):
        for ws in self.connections.values():
            try:
                await ws.send_json(message)
            except:
                pass
```

---

## Secure Message Validation

```python
from pydantic import BaseModel, field_validator
from typing import Literal, Any

class BaseMessage(BaseModel):
    action: str
    data: dict = {}

    model_config = {"extra": "forbid"}

class SubscribeMessage(BaseModel):
    action: Literal["subscribe"]
    channel: str

    @field_validator("channel")
    @classmethod
    def validate_channel(cls, v):
        allowed = {"notifications", "updates", "chat"}
        if v not in allowed:
            raise ValueError(f"Invalid channel: {v}")
        return v

class SendMessage(BaseModel):
    action: Literal["send"]
    recipient: str
    content: str

    @field_validator("content")
    @classmethod
    def validate_content(cls, v):
        if len(v) > 1000:
            raise ValueError("Message too long")
        return v

def parse_message(data: dict) -> BaseMessage:
    """Parse and validate WebSocket message."""
    action = data.get("action")

    validators = {
        "subscribe": SubscribeMessage,
        "send": SendMessage,
    }

    validator = validators.get(action, BaseMessage)
    return validator(**data)
```
