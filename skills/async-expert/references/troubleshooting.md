# Async Troubleshooting Guide

Common issues in async code and how to fix them.

---

## Issue 1: Blocking the Event Loop

**Problem**: Synchronous blocking operations freeze async execution

```python
# ❌ BAD: Blocks event loop
async def process_data():
    import time
    time.sleep(5)  # Blocks entire event loop!
    return "done"

# ✅ GOOD: Use async alternatives or run in executor
async def process_data():
    await asyncio.sleep(5)  # Non-blocking
    return "done"

# ✅ GOOD: Run blocking code in thread pool
async def process_data():
    import time
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, time.sleep, 5)
```

---

## Issue 2: Unhandled Promise Rejections / Exceptions

**Python**:
```python
# ❌ BAD: Fire-and-forget task, exceptions ignored
async def main():
    asyncio.create_task(failing_task())  # Exception will be lost!

# ✅ GOOD: Store task reference and await or add done callback
async def main():
    task = asyncio.create_task(failing_task())
    task.add_done_callback(lambda t: print(f"Task failed: {t.exception()}"))
```

**JavaScript**:
```javascript
// ❌ BAD: Unhandled rejection
async function main() {
  fetch('/api/data'); // Promise rejection ignored!
}

// ✅ GOOD: Handle errors
async function main() {
  try {
    await fetch('/api/data');
  } catch (error) {
    console.error('Request failed:', error);
  }
}

// Global handler for unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection:', reason);
});
```

---

## Issue 3: Race Conditions

```python
# ❌ BAD: Race condition with shared state
counter = 0

async def increment():
    global counter
    temp = counter
    await asyncio.sleep(0)  # Context switch!
    counter = temp + 1

# ✅ GOOD: Use locks for shared state
counter = 0
lock = asyncio.Lock()

async def increment():
    global counter
    async with lock:
        counter += 1
```

---

## Issue 4: Resource Leaks

```python
# ❌ BAD: Connection not closed on error
async def fetch_data():
    conn = await create_connection()
    data = await conn.fetch()  # If this fails, conn never closes
    await conn.close()
    return data

# ✅ GOOD: Use context manager
async def fetch_data():
    async with create_connection() as conn:
        return await conn.fetch()
```

---

## Issue 5: Deadlocks with Locks

```python
# ❌ BAD: Can deadlock if tasks acquire locks in different order
lock_a = asyncio.Lock()
lock_b = asyncio.Lock()

async def task1():
    async with lock_a:
        await asyncio.sleep(0.1)
        async with lock_b:  # Waiting for lock_b
            pass

async def task2():
    async with lock_b:
        await asyncio.sleep(0.1)
        async with lock_a:  # Waiting for lock_a - DEADLOCK!
            pass

# ✅ GOOD: Always acquire locks in same order, or use timeout
async def task1():
    async with asyncio.timeout(1.0):
        async with lock_a:
            async with lock_b:
                pass
```
