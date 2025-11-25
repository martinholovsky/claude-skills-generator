# Wake Word Detection Advanced Patterns

## Adaptive Threshold

```python
class AdaptiveDetector:
    """Adjust threshold based on environment."""

    def __init__(self, base_threshold: float = 0.5):
        self.base_threshold = base_threshold
        self.noise_level = 0.0
        self.false_positives = []

    def get_threshold(self) -> float:
        """Get current adaptive threshold."""
        # Increase threshold in noisy environment
        noise_factor = min(self.noise_level * 0.5, 0.3)

        # Increase after false positives
        fp_factor = len(self.false_positives) * 0.05

        return min(self.base_threshold + noise_factor + fp_factor, 0.9)

    def update_noise(self, audio: np.ndarray):
        """Update noise level estimate."""
        energy = np.mean(audio ** 2)
        self.noise_level = 0.9 * self.noise_level + 0.1 * energy

    def record_false_positive(self):
        """Record false positive for threshold adjustment."""
        self.false_positives.append(time.time())
        # Keep only recent
        hour_ago = time.time() - 3600
        self.false_positives = [t for t in self.false_positives if t > hour_ago]
```

## Multi-Stage Detection

```python
class TwoStageDetector:
    """Fast first stage, accurate second stage."""

    def __init__(self):
        # Fast, low accuracy model
        self.fast_model = Model(wakeword_models=["hey_jarvis_small"])
        # Slower, high accuracy model
        self.accurate_model = Model(wakeword_models=["hey_jarvis"])

    def detect(self, audio: np.ndarray) -> bool:
        # First stage: fast check
        fast_result = self.fast_model.predict(audio)
        if np.max(list(fast_result.values())[0]) < 0.3:
            return False  # Quick reject

        # Second stage: accurate check
        accurate_result = self.accurate_model.predict(audio)
        return np.max(list(accurate_result.values())[0]) > 0.6
```

## Context-Aware Detection

```python
class ContextAwareDetector:
    """Adjust detection based on context."""

    def __init__(self, detector: SecureWakeWordDetector):
        self.detector = detector
        self.context = "default"

    def set_context(self, context: str):
        """Set current context."""
        contexts = {
            "default": 0.5,
            "conversation": 0.7,  # Higher threshold during conversation
            "quiet": 0.4,  # Lower threshold in quiet environment
            "noisy": 0.6  # Higher threshold in noisy environment
        }
        self.detector.threshold = contexts.get(context, 0.5)
        self.context = context
        logger.info("context.updated", context=context)
```

## Performance Monitoring

```python
class DetectorMetrics:
    """Monitor wake word detector performance."""

    def __init__(self):
        self.detections = []
        self.cpu_usage = []
        self.latencies = []

    def record_detection(self, latency_ms: float):
        """Record detection event."""
        self.detections.append({
            "time": time.time(),
            "latency": latency_ms
        })

    def record_cpu(self, usage: float):
        """Record CPU usage."""
        self.cpu_usage.append({
            "time": time.time(),
            "usage": usage
        })

    def get_report(self) -> dict:
        """Get performance report."""
        return {
            "avg_latency_ms": np.mean([d["latency"] for d in self.detections]),
            "avg_cpu_percent": np.mean([c["usage"] for c in self.cpu_usage]),
            "detections_per_hour": len(self.detections)
        }
```

## Embedded Optimization

```python
class EmbeddedDetector:
    """Optimized for embedded systems."""

    def __init__(self):
        # Use quantized model
        self.model = Model(
            wakeword_models=["hey_jarvis"],
            inference_framework="onnx"  # Efficient runtime
        )

        # Reduce processing frequency
        self.process_every_n = 3
        self.frame_count = 0

    def on_audio(self, audio: np.ndarray):
        """Process with reduced frequency."""
        self.frame_count += 1

        # Only process every Nth frame
        if self.frame_count % self.process_every_n != 0:
            return

        # Quick energy check
        if np.mean(audio ** 2) < 0.0001:
            return  # Skip silence

        # Run detection
        self._detect(audio)
```
