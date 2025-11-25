# Python Advanced Patterns Reference

## Async Patterns

### Connection Pool Management

```python
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

engine = create_async_engine(
    "postgresql+asyncpg://...",
    pool_size=20,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=1800,
)

async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

@asynccontextmanager
async def get_db():
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
```

### Graceful Shutdown

```python
import asyncio
import signal

class GracefulShutdown:
    def __init__(self):
        self.shutdown_event = asyncio.Event()

    def setup(self):
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self.handle_signal)

    def handle_signal(self):
        self.shutdown_event.set()

    async def wait(self):
        await self.shutdown_event.wait()

# Usage
async def main():
    shutdown = GracefulShutdown()
    shutdown.setup()

    server_task = asyncio.create_task(run_server())

    await shutdown.wait()

    # Graceful shutdown
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass
```

---

## Type Safety Patterns

### Generic Repository

```python
from typing import TypeVar, Generic, Type
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

T = TypeVar('T')

class Repository(Generic[T]):
    def __init__(self, db: AsyncSession, model: Type[T]):
        self.db = db
        self.model = model

    async def get(self, id: int) -> T | None:
        return await self.db.get(self.model, id)

    async def create(self, **kwargs) -> T:
        instance = self.model(**kwargs)
        self.db.add(instance)
        await self.db.flush()
        return instance

    async def delete(self, id: int) -> None:
        instance = await self.get(id)
        if instance:
            await self.db.delete(instance)

# Usage
user_repo = Repository(db, User)
user = await user_repo.get(1)
```

### Protocol Types

```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class Hashable(Protocol):
    def hash(self) -> str: ...

@runtime_checkable
class Serializable(Protocol):
    def to_dict(self) -> dict: ...

def process(item: Hashable & Serializable) -> str:
    data = item.to_dict()
    return item.hash()
```

---

## Testing Patterns

### Fixtures with Dependency Injection

```python
import pytest
from unittest.mock import AsyncMock

@pytest.fixture
async def db_session():
    async with async_session() as session:
        yield session
        await session.rollback()

@pytest.fixture
def mock_external_api():
    mock = AsyncMock()
    mock.fetch_data.return_value = {"status": "ok"}
    return mock

@pytest.mark.asyncio
async def test_with_mocks(db_session, mock_external_api):
    service = MyService(db_session, mock_external_api)
    result = await service.process()
    assert result.status == "ok"
```

### Property-Based Testing

```python
from hypothesis import given, strategies as st

@given(st.text(min_size=1, max_size=100))
def test_username_validation(username):
    """Property: validation should never raise unexpected errors."""
    try:
        validated = validate_username(username)
        assert isinstance(validated, str)
    except ValueError:
        pass  # Expected for invalid input

@given(st.binary(min_size=1, max_size=10000))
def test_encryption_roundtrip(data):
    """Property: decrypt(encrypt(data)) == data."""
    key = generate_key()
    encrypted = encrypt(data, key)
    decrypted = decrypt(encrypted, key)
    assert decrypted == data
```

---

## Performance Patterns

### Caching with TTL

```python
from functools import lru_cache
from cachetools import TTLCache
import asyncio

# Sync caching
@lru_cache(maxsize=1000)
def compute_expensive(x: int) -> int:
    return x ** 2

# Async caching with TTL
cache = TTLCache(maxsize=1000, ttl=300)

async def cached_fetch(key: str) -> dict:
    if key in cache:
        return cache[key]

    result = await fetch_from_db(key)
    cache[key] = result
    return result
```

### Batch Processing

```python
from itertools import islice

def batched(iterable, n):
    """Yield successive n-sized chunks."""
    it = iter(iterable)
    while batch := list(islice(it, n)):
        yield batch

async def process_large_dataset(items: list):
    """Process in batches to manage memory."""
    for batch in batched(items, 100):
        await asyncio.gather(*[process_item(item) for item in batch])
```

---

## Dependency Injection

```python
from typing import Callable, TypeVar
from functools import wraps

T = TypeVar('T')

class Container:
    def __init__(self):
        self._services = {}
        self._factories = {}

    def register(self, interface: type, implementation: type):
        self._services[interface] = implementation

    def register_factory(self, interface: type, factory: Callable[[], T]):
        self._factories[interface] = factory

    def resolve(self, interface: type) -> T:
        if interface in self._factories:
            return self._factories[interface]()
        if interface in self._services:
            return self._services[interface]()
        raise ValueError(f"No registration for {interface}")

# Usage
container = Container()
container.register(UserRepository, SQLUserRepository)
container.register_factory(AsyncSession, get_db_session)

repo = container.resolve(UserRepository)
```
