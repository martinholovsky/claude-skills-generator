# Cloud API Integration Advanced Patterns

## Streaming Responses

```python
async def stream_claude_response(
    client: SecureClaudeClient,
    prompt: str
) -> AsyncGenerator[str, None]:
    """Stream responses for better UX."""

    with client.client.messages.stream(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    ) as stream:
        for text in stream.text_stream:
            yield text
```

## Response Caching

```python
import hashlib
from functools import lru_cache

class CachedAPIClient:
    """Cache API responses to reduce costs."""

    def __init__(self, client, cache_ttl: int = 3600):
        self.client = client
        self.cache = {}
        self.cache_ttl = cache_ttl

    async def generate(self, prompt: str, **kwargs) -> str:
        cache_key = self._make_key(prompt, kwargs)

        if cache_key in self.cache:
            entry = self.cache[cache_key]
            if time.time() - entry["time"] < self.cache_ttl:
                logger.info("cache.hit", key=cache_key[:16])
                return entry["response"]

        response = await self.client.generate(prompt, **kwargs)
        self.cache[cache_key] = {
            "response": response,
            "time": time.time()
        }

        return response

    def _make_key(self, prompt: str, kwargs: dict) -> str:
        data = f"{prompt}:{json.dumps(kwargs, sort_keys=True)}"
        return hashlib.sha256(data.encode()).hexdigest()
```

## Structured Output Parsing

```python
from pydantic import BaseModel

class TaskAnalysis(BaseModel):
    """Structured output from LLM."""
    intent: str
    entities: list[str]
    confidence: float
    action: str

async def analyze_task(prompt: str) -> TaskAnalysis:
    """Get structured output from Claude."""

    response = await client.generate(
        system="Analyze the user request and output JSON matching the schema.",
        prompt=f"Request: {prompt}\n\nOutput JSON with: intent, entities, confidence, action"
    )

    # Parse and validate
    try:
        data = json.loads(response)
        return TaskAnalysis(**data)
    except (json.JSONDecodeError, ValidationError) as e:
        logger.error("structured_output.parse_error", error=str(e))
        raise

# OpenAI structured outputs (native)
from openai import OpenAI

client = OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": prompt}],
    response_format={"type": "json_schema", "json_schema": TaskAnalysis.model_json_schema()}
)
```

## Circuit Breaker Pattern

```python
from datetime import datetime, timedelta

class CircuitBreaker:
    """Circuit breaker for API calls."""

    def __init__(self, failure_threshold: int = 5, reset_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.last_failure = None
        self.state = "closed"  # closed, open, half-open

    async def call(self, func, *args, **kwargs):
        if self.state == "open":
            if datetime.now() - self.last_failure > timedelta(seconds=self.reset_timeout):
                self.state = "half-open"
            else:
                raise CircuitOpenError("Circuit breaker is open")

        try:
            result = await func(*args, **kwargs)
            if self.state == "half-open":
                self.state = "closed"
                self.failures = 0
            return result

        except Exception as e:
            self.failures += 1
            self.last_failure = datetime.now()

            if self.failures >= self.failure_threshold:
                self.state = "open"
                logger.error("circuit_breaker.opened", failures=self.failures)

            raise
```

## Model Selection Strategy

```python
class ModelSelector:
    """Select optimal model based on task."""

    MODELS = {
        "simple": {"name": "claude-3-haiku-20240307", "cost": 0.25},
        "standard": {"name": "claude-sonnet-4-20250514", "cost": 3.0},
        "complex": {"name": "claude-3-opus-20240229", "cost": 15.0},
    }

    def select(self, task: str, token_estimate: int) -> str:
        """Select model based on task complexity and cost."""

        # Simple tasks: short, factual queries
        if token_estimate < 100 and any(kw in task.lower() for kw in ["what is", "define", "list"]):
            return self.MODELS["simple"]["name"]

        # Complex tasks: analysis, code generation, reasoning
        if any(kw in task.lower() for kw in ["analyze", "design", "architecture", "complex"]):
            return self.MODELS["complex"]["name"]

        # Default to standard
        return self.MODELS["standard"]["name"]
```

## Cost Tracking

```python
class CostTracker:
    """Track API costs in real-time."""

    # Pricing per 1K tokens (as of 2025)
    PRICING = {
        "claude-3-haiku-20240307": {"input": 0.00025, "output": 0.00125},
        "claude-sonnet-4-20250514": {"input": 0.003, "output": 0.015},
        "claude-3-opus-20240229": {"input": 0.015, "output": 0.075},
        "gpt-4o": {"input": 0.005, "output": 0.015},
    }

    def __init__(self):
        self.total_cost = 0.0
        self.by_model = defaultdict(float)

    def record(self, model: str, input_tokens: int, output_tokens: int):
        pricing = self.PRICING.get(model, {"input": 0.01, "output": 0.03})

        cost = (input_tokens * pricing["input"] + output_tokens * pricing["output"]) / 1000
        self.total_cost += cost
        self.by_model[model] += cost

        logger.info("api.cost",
                   model=model,
                   cost=cost,
                   total=self.total_cost)

        return cost
```
