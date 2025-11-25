# Advanced Async Patterns

This document contains advanced async programming patterns for experienced developers.

---

## Pattern 6: Async Iterator / Stream Processing

**Problem**: Process large datasets or streams without loading everything into memory

**Python**:
```python
import asyncio
from typing import AsyncIterator

async def fetch_page(page: int) -> list[dict]:
    """Fetch a page of data from API"""
    await asyncio.sleep(0.1)
    return [{"id": i, "page": page} for i in range(10)]

async def fetch_all_items() -> AsyncIterator[dict]:
    """Async generator that yields items one at a time"""
    page = 1
    while True:
        items = await fetch_page(page)
        if not items:
            break

        for item in items:
            yield item

        page += 1
        if page > 5:  # Limit for example
            break

async def process_stream():
    """Process items as they arrive"""
    async for item in fetch_all_items():
        # Process each item without loading all into memory
        result = await process_item(item)
        print(f"Processed: {result}")

async def process_item(item: dict) -> dict:
    await asyncio.sleep(0.01)
    return {**item, "processed": True}

# Advanced: Transform stream with async comprehension
async def main():
    processed_items = [
        item async for item in fetch_all_items()
        if item["id"] % 2 == 0  # Filter even IDs
    ]
    print(f"Processed {len(processed_items)} items")
```

**JavaScript**:
```javascript
// Async generator function
async function* fetchAllItems() {
  let page = 1;

  while (true) {
    const items = await fetchPage(page);
    if (items.length === 0) break;

    for (const item of items) {
      yield item;
    }

    page++;
    if (page > 5) break; // Limit for example
  }
}

async function fetchPage(page) {
  await new Promise(r => setTimeout(r, 100));
  return Array.from({ length: 10 }, (_, i) => ({ id: i, page }));
}

async function processStream() {
  // For-await-of loop
  for await (const item of fetchAllItems()) {
    const result = await processItem(item);
    console.log(`Processed: ${JSON.stringify(result)}`);
  }
}

async function processItem(item) {
  await new Promise(r => setTimeout(r, 10));
  return { ...item, processed: true };
}

// Usage
await processStream();
```

---

## Pattern 7: Circuit Breaker

**Problem**: Prevent cascading failures when a service is down

**Python**:
```python
import asyncio
from datetime import datetime, timedelta
from enum import Enum

class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered

class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: type = Exception
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception

        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED

    async def call(self, func, *args, **kwargs):
        if self.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if datetime.now() - self.last_failure_time > timedelta(seconds=self.recovery_timeout):
                self.state = CircuitState.HALF_OPEN
                print("Circuit breaker: HALF_OPEN (testing recovery)")
            else:
                raise Exception("Circuit breaker is OPEN")

        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exception as e:
            self._on_failure()
            raise

    def _on_success(self):
        self.failure_count = 0
        self.state = CircuitState.CLOSED
        print("Circuit breaker: CLOSED (normal operation)")

    def _on_failure(self):
        self.failure_count += 1
        self.last_failure_time = datetime.now()

        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            print(f"Circuit breaker: OPEN (failed {self.failure_count} times)")

# Usage
async def unreliable_service():
    """Simulates a failing service"""
    import random
    if random.random() < 0.8:
        raise ConnectionError("Service unavailable")
    return "Success"

async def main():
    breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=5.0)

    for i in range(10):
        try:
            result = await breaker.call(unreliable_service)
            print(f"Request {i}: {result}")
        except Exception as e:
            print(f"Request {i} failed: {e}")

        await asyncio.sleep(1)
```

---

## Pattern 8: Structured Concurrency / Task Groups

**Problem**: Manage lifecycle of multiple related tasks

**Python 3.11+**:
```python
import asyncio

async def task1():
    print("Task 1 starting")
    await asyncio.sleep(2)
    print("Task 1 done")
    return "result1"

async def task2():
    print("Task 2 starting")
    await asyncio.sleep(1)
    raise ValueError("Task 2 failed!")

async def task3():
    print("Task 3 starting")
    await asyncio.sleep(3)
    print("Task 3 done")
    return "result3"

async def main():
    # TaskGroup ensures all tasks are cleaned up
    try:
        async with asyncio.TaskGroup() as tg:
            t1 = tg.create_task(task1())
            t2 = tg.create_task(task2())
            t3 = tg.create_task(task3())

        # If we reach here, all tasks succeeded
        print(f"Results: {t1.result()}, {t3.result()}")
    except* ValueError as eg:
        # Exception group handling
        print(f"Tasks failed: {eg.exceptions}")
    # All tasks are guaranteed to be cancelled/completed
```

**JavaScript (AbortController for task groups)**:
```javascript
class TaskGroup {
  constructor() {
    this.tasks = [];
    this.controller = new AbortController();
  }

  add(fn) {
    const task = fn(this.controller.signal);
    this.tasks.push(task);
    return task;
  }

  async run() {
    try {
      return await Promise.all(this.tasks);
    } catch (error) {
      // Cancel all tasks on any failure
      this.controller.abort();
      throw error;
    }
  }
}

async function task1(signal) {
  console.log('Task 1 starting');
  await new Promise(r => setTimeout(r, 2000));
  if (signal.aborted) throw new Error('Aborted');
  console.log('Task 1 done');
  return 'result1';
}

async function task2(signal) {
  console.log('Task 2 starting');
  await new Promise(r => setTimeout(r, 1000));
  throw new Error('Task 2 failed!');
}

// Usage
const group = new TaskGroup();
group.add(task1);
group.add(task2);

try {
  await group.run();
} catch (error) {
  console.log('Task group failed:', error.message);
}
```
