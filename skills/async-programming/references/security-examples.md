# Async Programming Security Examples

## Race Condition Examples

### Double-Spending Prevention

```python
import asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# VULNERABLE - Double spending possible
async def spend_points_unsafe(db: AsyncSession, user_id: int, amount: int):
    user = await db.get(User, user_id)

    if user.points >= amount:
        await asyncio.sleep(0)  # Race window!
        user.points -= amount
        await db.commit()
        return True
    return False

# Attack: Two concurrent requests can both pass the check
# Request 1: Check (100 >= 80) -> passes
# Request 2: Check (100 >= 80) -> passes
# Request 1: Deduct -> 20 points
# Request 2: Deduct -> -60 points (negative!)

# SAFE - Atomic operation with row lock
async def spend_points_safe(db: AsyncSession, user_id: int, amount: int):
    async with db.begin():
        # Lock row for update
        stmt = (
            select(User)
            .where(User.id == user_id)
            .with_for_update()
        )
        user = (await db.execute(stmt)).scalar_one()

        if user.points < amount:
            return False

        user.points -= amount
        # Commit releases lock
        return True
```

### Session Hijacking via Race

```python
import asyncio

# VULNERABLE - Token reuse race
class UnsafeTokenStore:
    def __init__(self):
        self.tokens = {}

    async def use_token(self, token: str) -> bool:
        if token in self.tokens:
            await asyncio.sleep(0)  # Race window
            del self.tokens[token]
            return True
        return False

# Attack: Same one-time token used twice concurrently

# SAFE - Atomic check-and-delete
class SafeTokenStore:
    def __init__(self):
        self.tokens = {}
        self._lock = asyncio.Lock()

    async def use_token(self, token: str) -> bool:
        async with self._lock:
            if token in self.tokens:
                del self.tokens[token]
                return True
            return False
```

---

## CVE-2024-12254 Memory Exhaustion

```python
# VULNERABLE - writelines doesn't pause at high-water mark
async def stream_data_unsafe(writer):
    data = [b"x" * 1000000 for _ in range(1000)]
    writer.writelines(data)  # No backpressure, memory exhaustion

# SAFE - Manual backpressure handling
async def stream_data_safe(writer):
    data_chunks = [b"x" * 1000000 for _ in range(1000)]

    for chunk in data_chunks:
        writer.write(chunk)

        # Check if buffer is full
        if writer.transport.get_write_buffer_size() > 1024 * 1024:
            # Wait for drain
            await writer.drain()
```

---

## CVE-2023-28858/59 Redis Connection Pool Race

```python
# VULNERABLE - Connection corruption in async Redis
# When request is cancelled after send but before receive,
# the connection returns to pool with stale data

# Attack flow:
# 1. Request A sends command, gets cancelled before response
# 2. Connection returns to pool with response still buffered
# 3. Request B gets same connection
# 4. Request B receives Request A's response (data leak!)

# SAFE - Use connection per request or proper pool management
import redis.asyncio as redis

async def safe_redis_operation(client: redis.Redis, key: str):
    # Use pipeline for atomic operations
    async with client.pipeline(transaction=True) as pipe:
        await pipe.get(key)
        result = await pipe.execute()
        return result[0]

# Or use connection context
async def safe_with_connection(pool):
    async with pool.connection() as conn:
        return await conn.execute("GET", "key")
```

---

## Resource Leak Prevention

### Connection Pool Leak

```python
# VULNERABLE - Leak on exception
async def query_unsafe(pool):
    conn = await pool.acquire()
    result = await conn.fetch("SELECT * FROM data")  # Exception = leak
    await pool.release(conn)
    return result

# SAFE - Context manager ensures cleanup
async def query_safe(pool):
    async with pool.acquire() as conn:
        return await conn.fetch("SELECT * FROM data")
```

### File Handle Leak

```python
import aiofiles

# VULNERABLE
async def read_unsafe(path):
    f = await aiofiles.open(path)
    data = await f.read()  # Exception = leak
    await f.close()
    return data

# SAFE
async def read_safe(path):
    async with aiofiles.open(path) as f:
        return await f.read()
```

---

## Deadlock Prevention

### Consistent Lock Ordering

```python
class Account:
    def __init__(self, id: int, balance: int):
        self.id = id
        self.balance = balance
        self.lock = asyncio.Lock()

# VULNERABLE - Deadlock possible
async def transfer_deadlock(a: Account, b: Account, amount: int):
    # Task 1: transfer(a, b) locks a, waits for b
    # Task 2: transfer(b, a) locks b, waits for a
    # -> Deadlock!
    async with a.lock:
        async with b.lock:
            if a.balance >= amount:
                a.balance -= amount
                b.balance += amount

# SAFE - Consistent ordering by ID
async def transfer_safe(a: Account, b: Account, amount: int):
    first, second = (a, b) if a.id < b.id else (b, a)

    async with first.lock:
        async with second.lock:
            if a.balance >= amount:
                a.balance -= amount
                b.balance += amount
```

### Timeout on Locks

```python
async def with_lock_timeout(lock: asyncio.Lock, timeout: float):
    try:
        await asyncio.wait_for(lock.acquire(), timeout=timeout)
        yield
    except asyncio.TimeoutError:
        raise DeadlockError("Could not acquire lock")
    finally:
        if lock.locked():
            lock.release()

async def safe_operation(lock):
    async with with_lock_timeout(lock, timeout=5.0):
        await do_work()
```

---

## Cancellation Safety

```python
import asyncio

async def cancellation_safe_operation():
    """Handle cancellation gracefully."""
    conn = None
    try:
        conn = await connect()
        result = await conn.execute()
        return result
    except asyncio.CancelledError:
        # Cleanup on cancellation
        if conn:
            await conn.rollback()
        raise  # Re-raise to propagate cancellation
    finally:
        if conn:
            await conn.close()

# Using shield for critical sections
async def critical_operation():
    # This section cannot be cancelled
    await asyncio.shield(save_critical_data())
```

---

## Semaphore for Resource Limiting

```python
class DatabasePool:
    """Limit concurrent database connections."""

    def __init__(self, max_connections: int = 10):
        self._semaphore = asyncio.Semaphore(max_connections)
        self._connections: list = []

    async def acquire(self):
        await self._semaphore.acquire()
        conn = await create_connection()
        return conn

    async def release(self, conn):
        await conn.close()
        self._semaphore.release()

# Usage
pool = DatabasePool(max_connections=10)

async def query():
    conn = await pool.acquire()
    try:
        return await conn.fetch("...")
    finally:
        await pool.release(conn)
```
