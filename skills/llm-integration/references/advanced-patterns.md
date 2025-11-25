# LLM Integration Advanced Patterns

## Model Loading Optimization

### Lazy Model Loading with Caching

```python
from functools import lru_cache
from threading import Lock

class ModelManager:
    """Thread-safe model manager with lazy loading."""

    def __init__(self, models_dir: str):
        self.models_dir = Path(models_dir)
        self._models = {}
        self._lock = Lock()

    def get_model(self, name: str) -> Llama:
        """Get or load model (thread-safe singleton per model)."""
        if name not in self._models:
            with self._lock:
                if name not in self._models:
                    self._models[name] = self._load_model(name)
        return self._models[name]

    def _load_model(self, name: str) -> Llama:
        path = self.models_dir / f"{name}.gguf"
        logger.info("model.loading", name=name)

        model = Llama(
            model_path=str(path),
            n_ctx=4096,
            n_batch=512,
            n_threads=os.cpu_count() // 2,
            use_mmap=True,  # Memory-mapped for efficiency
            use_mlock=False  # Don't lock in RAM
        )

        logger.info("model.loaded", name=name, params=model.n_params())
        return model
```

### GPU Layer Optimization

```python
def configure_gpu_layers(model_size_gb: float, vram_gb: float) -> int:
    """Calculate optimal GPU layers based on available VRAM."""
    # Reserve 2GB for system/other apps
    available_vram = vram_gb - 2

    # Estimate layers that fit
    # Each layer ~= model_size / 32 layers
    layer_size_gb = model_size_gb / 32

    n_gpu_layers = int(available_vram / layer_size_gb)
    return min(n_gpu_layers, 32)  # Cap at 32 layers

# Usage
llm = Llama(
    model_path="model.gguf",
    n_gpu_layers=configure_gpu_layers(7.0, 8.0)  # 7B model, 8GB VRAM
)
```

## Context Window Management

### Sliding Window for Long Conversations

```python
class ConversationManager:
    """Manage conversation history within context limits."""

    def __init__(self, model: Llama, max_context: int = 4096):
        self.model = model
        self.max_context = max_context
        self.history = []

    def add_message(self, role: str, content: str):
        self.history.append({"role": role, "content": content})
        self._trim_to_context()

    def _trim_to_context(self):
        """Remove oldest messages if exceeding context."""
        while self._total_tokens() > self.max_context * 0.8:
            if len(self.history) > 2:  # Keep at least system + last user
                self.history.pop(1)  # Remove oldest after system
            else:
                break

    def _total_tokens(self) -> int:
        text = "\n".join(m["content"] for m in self.history)
        return len(self.model.tokenize(text.encode()))

    def get_prompt(self) -> str:
        """Build prompt from history."""
        return "\n".join(
            f"{m['role']}: {m['content']}"
            for m in self.history
        )
```

## Streaming with Backpressure

```python
import asyncio
from collections import deque

class BackpressureStream:
    """Stream tokens with backpressure handling."""

    def __init__(self, max_buffer: int = 100):
        self.buffer = deque(maxlen=max_buffer)
        self.event = asyncio.Event()

    async def produce(self, model, prompt: str):
        """Generate tokens into buffer."""
        for token in model(prompt, stream=True):
            while len(self.buffer) >= self.buffer.maxlen:
                await asyncio.sleep(0.01)  # Backpressure

            self.buffer.append(token["choices"][0]["text"])
            self.event.set()

    async def consume(self):
        """Consume tokens from buffer."""
        while True:
            if self.buffer:
                yield self.buffer.popleft()
            else:
                self.event.clear()
                await self.event.wait()
```

## Multi-Model Routing

```python
class ModelRouter:
    """Route requests to appropriate models."""

    def __init__(self, model_manager: ModelManager):
        self.manager = model_manager
        self.routes = {
            "chat": "llama-7b-chat",
            "code": "codellama-7b",
            "summarize": "mistral-7b",
            "fast": "phi-2"  # Small model for quick responses
        }

    def route(self, task: str, prompt: str) -> str:
        """Route to appropriate model based on task."""
        model_name = self.routes.get(task, "llama-7b-chat")
        model = self.manager.get_model(model_name)

        logger.info("model.routed", task=task, model=model_name)
        return model(prompt)["choices"][0]["text"]
```

## Batch Inference for Throughput

```python
from concurrent.futures import ThreadPoolExecutor
from typing import List

class BatchInference:
    """Process multiple prompts efficiently."""

    def __init__(self, model: Llama, max_workers: int = 4):
        self.model = model
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    def batch_generate(self, prompts: List[str]) -> List[str]:
        """Generate responses for multiple prompts."""
        futures = [
            self.executor.submit(self._generate_one, prompt)
            for prompt in prompts
        ]

        return [f.result() for f in futures]

    def _generate_one(self, prompt: str) -> str:
        return self.model(prompt)["choices"][0]["text"]
```

## KV Cache Persistence

```python
import pickle
from pathlib import Path

class PersistentKVCache:
    """Save and restore KV cache for faster context loading."""

    def __init__(self, cache_dir: str):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

    def save_state(self, model: Llama, session_id: str):
        """Save model state for later restoration."""
        state = model.save_state()
        cache_path = self.cache_dir / f"{session_id}.cache"

        with open(cache_path, "wb") as f:
            pickle.dump(state, f)

        logger.info("kv_cache.saved", session_id=session_id)

    def load_state(self, model: Llama, session_id: str) -> bool:
        """Restore model state from cache."""
        cache_path = self.cache_dir / f"{session_id}.cache"

        if not cache_path.exists():
            return False

        with open(cache_path, "rb") as f:
            state = pickle.load(f)

        model.load_state(state)
        logger.info("kv_cache.loaded", session_id=session_id)
        return True
```

## Quantization Selection Guide

| Model Size | RAM Available | Recommended Quantization | Quality |
|------------|---------------|-------------------------|---------|
| 7B | 4GB | Q4_K_S | Good |
| 7B | 8GB | Q5_K_M | Better |
| 7B | 16GB | Q8_0 | Best |
| 13B | 8GB | Q4_K_S | Good |
| 13B | 16GB | Q5_K_M | Better |
| 13B | 32GB | Q8_0 | Best |

```python
def select_quantization(model_params_b: int, ram_gb: int) -> str:
    """Select appropriate quantization level."""
    # Estimate memory per quantization level
    q4_mem = model_params_b * 0.5  # ~0.5 bytes per param
    q5_mem = model_params_b * 0.625
    q8_mem = model_params_b * 1.0

    available = ram_gb - 2  # Reserve 2GB

    if q8_mem <= available:
        return "Q8_0"
    elif q5_mem <= available:
        return "Q5_K_M"
    elif q4_mem <= available:
        return "Q4_K_S"
    else:
        raise ValueError(f"Insufficient RAM for {model_params_b}B model")
```
