# WebSocket Advanced Patterns Reference

## Pub/Sub Pattern

```python
from collections import defaultdict
import asyncio

class PubSubManager:
    def __init__(self):
        self.subscriptions: dict[str, set[str]] = defaultdict(set)  # channel -> user_ids
        self.user_channels: dict[str, set[str]] = defaultdict(set)  # user_id -> channels
        self._lock = asyncio.Lock()

    async def subscribe(self, user_id: str, channel: str):
        async with self._lock:
            self.subscriptions[channel].add(user_id)
            self.user_channels[user_id].add(channel)

    async def unsubscribe(self, user_id: str, channel: str):
        async with self._lock:
            self.subscriptions[channel].discard(user_id)
            self.user_channels[user_id].discard(channel)

    async def publish(self, channel: str, message: dict):
        subscribers = self.subscriptions.get(channel, set())
        for user_id in subscribers:
            await connection_manager.send_to_user(user_id, {
                "type": "message",
                "channel": channel,
                "data": message
            })

    async def cleanup_user(self, user_id: str):
        async with self._lock:
            for channel in self.user_channels.get(user_id, set()):
                self.subscriptions[channel].discard(user_id)
            self.user_channels.pop(user_id, None)

pubsub = PubSubManager()
```

---

## Heartbeat/Ping-Pong

```python
import asyncio

async def websocket_with_heartbeat(websocket: WebSocket, user: User):
    """WebSocket handler with heartbeat to detect dead connections."""

    async def heartbeat():
        while True:
            await asyncio.sleep(30)
            try:
                await websocket.send_json({"type": "ping"})
            except:
                break

    heartbeat_task = asyncio.create_task(heartbeat())

    try:
        while True:
            data = await asyncio.wait_for(
                websocket.receive_json(),
                timeout=60  # Expect pong within 60s
            )

            if data.get("type") == "pong":
                continue

            await handle_message(websocket, user, data)

    except asyncio.TimeoutError:
        logger.info(f"Connection timeout: user={user.id}")
    finally:
        heartbeat_task.cancel()
```

---

## Reconnection with State Recovery

```python
# Server-side: Track message sequence
class StatefulConnection:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.sequence = 0
        self.pending_messages: list[dict] = []

    def next_sequence(self) -> int:
        self.sequence += 1
        return self.sequence

    def store_message(self, message: dict):
        message["seq"] = self.next_sequence()
        self.pending_messages.append(message)
        # Keep only last 100 messages
        if len(self.pending_messages) > 100:
            self.pending_messages.pop(0)

    def get_missed_messages(self, last_seq: int) -> list[dict]:
        return [m for m in self.pending_messages if m["seq"] > last_seq]

# Client-side recovery
class ReconnectingWebSocket {
    constructor(url, token) {
        this.lastSeq = 0;
    }

    connect() {
        const wsUrl = `${this.url}?token=${this.token}&last_seq=${this.lastSeq}`;
        this.ws = new WebSocket(wsUrl);

        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.seq) {
                this.lastSeq = data.seq;
            }
        };
    }
}
```

---

## Load Balancing with Redis

```python
import aioredis

class DistributedWebSocket:
    """WebSocket handler for horizontally scaled deployment."""

    def __init__(self):
        self.redis = None
        self.local_connections: dict[str, WebSocket] = {}

    async def init(self):
        self.redis = await aioredis.from_url("redis://localhost")
        # Subscribe to broadcast channel
        self.pubsub = self.redis.pubsub()
        await self.pubsub.subscribe("ws:broadcast")

        # Start listener
        asyncio.create_task(self.listen_broadcasts())

    async def listen_broadcasts(self):
        async for message in self.pubsub.listen():
            if message["type"] == "message":
                data = json.loads(message["data"])
                user_id = data.get("user_id")
                if user_id in self.local_connections:
                    await self.local_connections[user_id].send_json(data["message"])

    async def send_to_user(self, user_id: str, message: dict):
        # Try local first
        if user_id in self.local_connections:
            await self.local_connections[user_id].send_json(message)
        else:
            # Publish to Redis for other instances
            await self.redis.publish("ws:broadcast", json.dumps({
                "user_id": user_id,
                "message": message
            }))

    async def register(self, user_id: str, websocket: WebSocket):
        self.local_connections[user_id] = websocket
        await self.redis.sadd("ws:online", user_id)

    async def unregister(self, user_id: str):
        self.local_connections.pop(user_id, None)
        await self.redis.srem("ws:online", user_id)
```

---

## Binary Message Handling

```python
import struct

async def handle_binary_message(websocket: WebSocket, data: bytes):
    """Handle binary WebSocket messages."""

    if len(data) < 4:
        return

    # First 4 bytes = message type
    msg_type = struct.unpack(">I", data[:4])[0]

    handlers = {
        1: handle_audio,
        2: handle_image,
        3: handle_file,
    }

    handler = handlers.get(msg_type)
    if handler:
        await handler(websocket, data[4:])

async def handle_audio(websocket: WebSocket, data: bytes):
    # Process audio chunk
    if len(data) > 1024 * 1024:  # 1MB limit
        return

    # ... process
```

---

## Testing Utilities

```python
import pytest
from fastapi.testclient import TestClient

class WebSocketTestClient:
    def __init__(self, app, token: str, origin: str):
        self.client = TestClient(app)
        self.token = token
        self.origin = origin

    def connect(self):
        return self.client.websocket_connect(
            f"/ws?token={self.token}",
            headers={"Origin": self.origin}
        )

@pytest.fixture
def ws_client(app, test_user_token):
    return WebSocketTestClient(
        app,
        test_user_token,
        "https://app.example.com"
    )

def test_subscribe_and_receive(ws_client):
    with ws_client.connect() as ws:
        ws.send_json({"action": "subscribe", "channel": "updates"})
        response = ws.receive_json()
        assert response["status"] == "subscribed"
```
