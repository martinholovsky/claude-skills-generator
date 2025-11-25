# Async Anti-Patterns

Common mistakes to avoid in asynchronous programming.

---

## Mistake 1: Forgetting await

```python
# ❌ BAD: Forgot await, returns coroutine object
async def get_data():
    result = fetch_data()  # Missing await!
    return result  # Returns coroutine, not data

# ✅ GOOD
async def get_data():
    result = await fetch_data()
    return result
```

---

## Mistake 2: Sequential When You Want Parallel

```python
# ❌ BAD: Sequential execution (slow)
async def fetch_all():
    user = await fetch_user()      # Wait 1s
    posts = await fetch_posts()    # Wait 1s
    comments = await fetch_comments()  # Wait 1s
    # Total: 3s

# ✅ GOOD: Parallel execution (fast)
async def fetch_all():
    user, posts, comments = await asyncio.gather(
        fetch_user(),
        fetch_posts(),
        fetch_comments()
    )
    # Total: 1s (assuming they run in parallel)
```

---

## Mistake 3: Creating Too Many Concurrent Tasks

```python
# ❌ BAD: Create 10,000 concurrent connections
async def process_all(items):
    tasks = [process_item(item) for item in items]  # 10k tasks!
    return await asyncio.gather(*tasks)

# ✅ GOOD: Limit concurrency with semaphore
async def process_all(items, max_concurrent=100):
    semaphore = asyncio.Semaphore(max_concurrent)

    async def bounded_process(item):
        async with semaphore:
            return await process_item(item)

    tasks = [bounded_process(item) for item in items]
    return await asyncio.gather(*tasks)
```

---

## Mistake 4: Not Handling Cancellation

```python
# ❌ BAD: Ignores cancellation
async def worker():
    try:
        while True:
            await do_work()
    except asyncio.CancelledError:
        pass  # Silently swallow cancellation!

# ✅ GOOD: Handle cleanup and re-raise
async def worker():
    try:
        while True:
            await do_work()
    except asyncio.CancelledError:
        await cleanup()
        raise  # Re-raise to signal cancellation
```

---

## Mistake 5: Mixing Async and Sync Code Incorrectly

```javascript
// ❌ BAD: Mixing callbacks with promises
async function fetchData() {
  return new Promise((resolve) => {
    fs.readFile('file.txt', (err, data) => {
      if (err) throw err; // This won't be caught by try/catch!
      resolve(data);
    });
  });
}

// ✅ GOOD: Properly handle errors in callbacks
async function fetchData() {
  return new Promise((resolve, reject) => {
    fs.readFile('file.txt', (err, data) => {
      if (err) reject(err);
      else resolve(data);
    });
  });
}

// ✅ BETTER: Use promisified version
import { readFile } from 'fs/promises';
async function fetchData() {
  return await readFile('file.txt');
}
```

---

## Mistake 6: Ignoring Backpressure

```python
# ❌ BAD: Producer overwhelms consumer
async def producer(queue):
    for i in range(1_000_000):
        await queue.put(i)  # Unbounded queue grows forever

# ✅ GOOD: Bounded queue provides backpressure
async def producer(queue):
    # queue = asyncio.Queue(maxsize=100)
    for i in range(1_000_000):
        await queue.put(i)  # Blocks when queue is full
```

---

## Mistake 7: Not Setting Timeouts

```python
# ❌ BAD: Can hang forever
async def fetch_data():
    return await client.get('http://slow-server.com')

# ✅ GOOD: Always use timeouts
async def fetch_data():
    async with asyncio.timeout(5.0):
        return await client.get('http://slow-server.com')
```

---

## Mistake 8: Using time.sleep Instead of asyncio.sleep

```python
# ❌ BAD: Blocks the entire event loop
async def delayed_task():
    import time
    time.sleep(5)  # Everything freezes!

# ✅ GOOD: Non-blocking sleep
async def delayed_task():
    await asyncio.sleep(5)  # Other tasks can run
```
