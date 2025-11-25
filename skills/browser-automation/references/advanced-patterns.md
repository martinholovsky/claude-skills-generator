# Browser Automation - Advanced Patterns

## Pattern: Context Isolation

```python
from playwright.sync_api import sync_playwright

class IsolatedBrowserSession:
    """Fully isolated browser sessions."""

    def __init__(self):
        self.playwright = None
        self.browser = None

    def create_isolated_context(self):
        """Create isolated browser context."""
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(headless=True)

        context = self.browser.new_context(
            ignore_https_errors=False,
            bypass_csp=False,
            storage_state=None,  # No stored state
        )

        # Prevent data persistence
        context.add_init_script('''
            // Disable localStorage and sessionStorage
            Object.defineProperty(window, 'localStorage', {
                value: {
                    getItem: () => null,
                    setItem: () => {},
                    removeItem: () => {},
                    clear: () => {}
                }
            });
        ''')

        return context

    def cleanup(self):
        """Complete cleanup."""
        if self.browser:
            for context in self.browser.contexts:
                context.clear_cookies()
                context.close()
            self.browser.close()
        if self.playwright:
            self.playwright.stop()
```

## Pattern: Parallel Page Execution

```python
import asyncio
from playwright.async_api import async_playwright

class ParallelBrowser:
    """Execute browser operations in parallel."""

    def __init__(self, max_concurrent: int = 5):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def process_urls(self, urls: list, processor) -> list:
        """Process multiple URLs in parallel."""
        async with async_playwright() as p:
            browser = await p.chromium.launch()

            async def process_one(url):
                async with self.semaphore:
                    context = await browser.new_context()
                    page = await context.new_page()
                    try:
                        result = await processor(page, url)
                        return result
                    finally:
                        await context.close()

            results = await asyncio.gather(
                *[process_one(url) for url in urls],
                return_exceptions=True
            )

            await browser.close()
            return results
```

## Pattern: Retry with Backoff

```python
import asyncio

class RetryableBrowserAction:
    """Retry browser actions with exponential backoff."""

    def __init__(self, max_retries: int = 3):
        self.max_retries = max_retries

    async def execute(self, action, *args, **kwargs):
        """Execute with retry."""
        for attempt in range(self.max_retries):
            try:
                return await action(*args, **kwargs)
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise
                wait = 2 ** attempt
                await asyncio.sleep(wait)
```

## Pattern: Response Caching

```python
import hashlib

class ResponseCache:
    """Cache browser responses."""

    def __init__(self, max_size: int = 100):
        self.cache = {}
        self.max_size = max_size

    def get_key(self, url: str, method: str = 'GET') -> str:
        """Generate cache key."""
        return hashlib.sha256(f"{method}:{url}".encode()).hexdigest()

    def get(self, url: str) -> str | None:
        """Get cached response."""
        key = self.get_key(url)
        if key in self.cache:
            return self.cache[key]['content']
        return None

    def set(self, url: str, content: str):
        """Cache response."""
        if len(self.cache) >= self.max_size:
            # Remove oldest
            oldest = min(self.cache, key=lambda k: self.cache[k]['time'])
            del self.cache[oldest]

        key = self.get_key(url)
        self.cache[key] = {
            'content': content,
            'time': time.time()
        }
```

## Pattern: Page Object Model

```python
class SecurePageObject:
    """Base class for page objects with security."""

    def __init__(self, page, automation: SecureBrowserAutomation):
        self.page = page
        self.automation = automation

    def navigate(self):
        """Navigate to page (implement in subclass)."""
        raise NotImplementedError

    def _safe_fill(self, selector: str, value: str):
        """Fill with security validation."""
        element = self.page.locator(selector)

        # Check element type
        if element.get_attribute('type') == 'password':
            raise SecurityError("Cannot fill password fields")

        element.fill(value)

    def _safe_click(self, selector: str):
        """Click with logging."""
        self.automation._audit_log('click', selector)
        self.page.locator(selector).click()


class SearchPage(SecurePageObject):
    """Example secure page object."""

    URL = 'https://example.com/search'

    def navigate(self):
        self.automation.navigate(self.URL)

    def search(self, query: str):
        self._safe_fill('#search-input', query)
        self._safe_click('#search-button')

    def get_results(self) -> list:
        elements = self.page.locator('.result-item').all()
        return [el.text_content() for el in elements]
```

## Pattern: Network Interception

```python
class NetworkInterceptor:
    """Intercept and modify network requests."""

    def __init__(self, page):
        self.page = page
        self.intercepted = []

    def setup(self):
        """Setup request interception."""
        async def handle(route, request):
            self.intercepted.append({
                'url': request.url,
                'method': request.method,
                'headers': dict(request.headers)
            })

            # Add custom headers
            headers = {**request.headers}
            headers['X-Automated'] = 'true'

            await route.continue_(headers=headers)

        self.page.route('**/*', handle)

    def get_api_calls(self) -> list:
        """Get intercepted API calls."""
        return [
            r for r in self.intercepted
            if '/api/' in r['url']
        ]
```
