# Async Programming Advanced Patterns

## Task Management

### Task Group Pattern (Python 3.11+)

```python
import asyncio

async def process_items(items: list):
    """Process items with proper error handling."""
    async with asyncio.TaskGroup() as tg:
        tasks = [
            tg.create_task(process_item(item))
            for item in items
        ]
    # All tasks complete or error propagates
    return [task.result() for task in tasks]
```

### Supervised Tasks

```python
class TaskSupervisor:
    """Manage background tasks with restart on failure."""

    def __init__(self):
        self.tasks: dict[str, asyncio.Task] = {}
        self.should_run = True

    async def start_task(self, name: str, coro_func):
        async def supervised():
            while self.should_run:
                try:
                    await coro_func()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Task {name} failed: {e}")
                    await asyncio.sleep(1)  # Backoff

        self.tasks[name] = asyncio.create_task(supervised())

    async def stop_all(self):
        self.should_run = False
        for task in self.tasks.values():
            task.cancel()
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)
```

---

## Concurrency Patterns

### Worker Pool

```python
import asyncio
from typing import Callable, Any

class WorkerPool:
    def __init__(self, num_workers: int = 4):
        self.queue: asyncio.Queue = asyncio.Queue()
        self.num_workers = num_workers
        self.workers: list[asyncio.Task] = []

    async def start(self):
        for i in range(self.num_workers):
            worker = asyncio.create_task(self._worker(i))
            self.workers.append(worker)

    async def _worker(self, worker_id: int):
        while True:
            job, future = await self.queue.get()
            try:
                result = await job()
                future.set_result(result)
            except Exception as e:
                future.set_exception(e)
            finally:
                self.queue.task_done()

    async def submit(self, job: Callable) -> Any:
        future = asyncio.get_event_loop().create_future()
        await self.queue.put((job, future))
        return await future

    async def shutdown(self):
        await self.queue.join()
        for worker in self.workers:
            worker.cancel()
```

### Fan-Out/Fan-In

```python
async def fan_out_fan_in(items: list, process_func, aggregate_func):
    """
    Fan-out: Process items concurrently
    Fan-in: Aggregate results
    """
    # Fan-out
    tasks = [asyncio.create_task(process_func(item)) for item in items]
    results = await asyncio.gather(*tasks)

    # Fan-in
    return aggregate_func(results)

# Usage
async def analyze_urls(urls: list[str]):
    return await fan_out_fan_in(
        urls,
        fetch_and_analyze,
        lambda results: {"total": len(results), "data": results}
    )
```

---

## Stream Processing

### Async Generator Pipeline

```python
async def read_lines(path: str):
    """Async generator for reading file lines."""
    async with aiofiles.open(path) as f:
        async for line in f:
            yield line.strip()

async def filter_lines(lines, predicate):
    """Filter async generator."""
    async for line in lines:
        if predicate(line):
            yield line

async def process_lines(lines):
    """Process filtered lines."""
    async for line in lines:
        yield await process(line)

# Pipeline usage
async def pipeline(path: str):
    lines = read_lines(path)
    filtered = filter_lines(lines, lambda l: l.startswith("ERROR"))
    processed = process_lines(filtered)

    async for result in processed:
        await save(result)
```

### Buffered Stream

```python
class BufferedStream:
    """Buffer async stream for batch processing."""

    def __init__(self, source, buffer_size: int = 100):
        self.source = source
        self.buffer_size = buffer_size

    async def batches(self):
        buffer = []
        async for item in self.source:
            buffer.append(item)
            if len(buffer) >= self.buffer_size:
                yield buffer
                buffer = []
        if buffer:
            yield buffer

# Usage
async def batch_insert(items_stream):
    buffered = BufferedStream(items_stream, buffer_size=100)
    async for batch in buffered.batches():
        await db.insert_many(batch)
```

---

## Rust Async Patterns

### Tokio Select

```rust
use tokio::select;
use tokio::sync::mpsc;

async fn server(mut shutdown: mpsc::Receiver<()>) {
    loop {
        select! {
            _ = shutdown.recv() => {
                println!("Shutting down");
                break;
            }
            result = handle_connection() => {
                if let Err(e) = result {
                    eprintln!("Error: {}", e);
                }
            }
        }
    }
}
```

### Tokio Spawn with JoinHandle

```rust
use tokio::task::JoinHandle;

struct TaskManager {
    tasks: Vec<JoinHandle<()>>,
}

impl TaskManager {
    fn spawn(&mut self, task: impl Future<Output = ()> + Send + 'static) {
        self.tasks.push(tokio::spawn(task));
    }

    async fn shutdown(self) {
        for task in self.tasks {
            let _ = task.await;
        }
    }
}
```

### RwLock for Read-Heavy Workloads

```rust
use std::sync::Arc;
use tokio::sync::RwLock;

struct Cache {
    data: Arc<RwLock<HashMap<String, String>>>,
}

impl Cache {
    async fn get(&self, key: &str) -> Option<String> {
        let read = self.data.read().await;
        read.get(key).cloned()
    }

    async fn set(&self, key: String, value: String) {
        let mut write = self.data.write().await;
        write.insert(key, value);
    }
}
```

---

## Testing Async Code

### Deterministic Testing

```python
import pytest
import asyncio

@pytest.fixture
def event_loop():
    """Create event loop for tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.mark.asyncio
async def test_concurrent_operations():
    """Test behavior under concurrent load."""
    counter = SafeCounter()

    # Create many concurrent increments
    tasks = [counter.increment() for _ in range(1000)]
    await asyncio.gather(*tasks)

    assert await counter.get() == 1000
```

### Testing Race Conditions

```python
@pytest.mark.asyncio
async def test_race_condition_scenario():
    """Explicitly test race condition scenario."""
    account = Account(balance=100)

    async def withdraw(amount):
        if account.balance >= amount:
            await asyncio.sleep(0.001)  # Force context switch
            account.balance -= amount
            return True
        return False

    # Run concurrent withdrawals
    results = await asyncio.gather(
        withdraw(60),
        withdraw(60),
        withdraw(60)
    )

    # Without protection: multiple succeed, balance goes negative
    # With protection: only one succeeds
    assert account.balance >= 0, "Race condition: negative balance"
```

### Mocking Async Functions

```python
from unittest.mock import AsyncMock

@pytest.mark.asyncio
async def test_with_mock():
    mock_fetch = AsyncMock(return_value={"data": "test"})

    result = await process_with_fetch(mock_fetch)

    mock_fetch.assert_called_once()
    assert result["data"] == "test"
```

---

## Performance Optimization

### Connection Pooling

```python
from asyncpg import create_pool

async def optimized_queries(dsn: str):
    pool = await create_pool(
        dsn,
        min_size=5,
        max_size=20,
        command_timeout=30
    )

    async def query(sql, *args):
        async with pool.acquire() as conn:
            return await conn.fetch(sql, *args)

    return query
```

### Caching with Async Lock

```python
class AsyncCache:
    def __init__(self):
        self._cache = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

    async def get_or_set(self, key: str, factory):
        # Fast path - no lock
        if key in self._cache:
            return self._cache[key]

        # Get per-key lock
        async with self._global_lock:
            if key not in self._locks:
                self._locks[key] = asyncio.Lock()
            lock = self._locks[key]

        # Compute with per-key lock
        async with lock:
            if key not in self._cache:
                self._cache[key] = await factory()
            return self._cache[key]
```
