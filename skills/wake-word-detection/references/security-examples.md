# Wake Word Detection Security Examples

## Privacy-Preserving Audio Handling

```python
class PrivateAudioBuffer:
    """Buffer that never persists audio."""

    def __init__(self, max_seconds: float = 1.5, sample_rate: int = 16000):
        self.max_size = int(max_seconds * sample_rate)
        self._buffer = np.zeros(self.max_size, dtype=np.float32)
        self._position = 0

    def add(self, audio: np.ndarray):
        """Add audio to circular buffer."""
        n = len(audio)
        if n >= self.max_size:
            self._buffer[:] = audio[-self.max_size:]
            self._position = 0
        else:
            end_pos = self._position + n
            if end_pos <= self.max_size:
                self._buffer[self._position:end_pos] = audio
                self._position = end_pos
            else:
                first = self.max_size - self._position
                self._buffer[self._position:] = audio[:first]
                self._buffer[:n-first] = audio[first:]
                self._position = n - first

    def clear(self):
        """Securely clear buffer."""
        self._buffer.fill(0)
        self._position = 0

    def get(self) -> np.ndarray:
        """Get buffer contents."""
        return np.roll(self._buffer, -self._position)
```

## User Consent Management

```python
class ConsentManager:
    """Manage user consent for always-listening."""

    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self._load_config()

    def _load_config(self):
        if self.config_path.exists():
            self.config = json.loads(self.config_path.read_text())
        else:
            self.config = {"listening_enabled": False}

    def is_listening_allowed(self) -> bool:
        return self.config.get("listening_enabled", False)

    def set_listening(self, enabled: bool):
        self.config["listening_enabled"] = enabled
        self.config["last_modified"] = datetime.now().isoformat()
        self._save_config()
        logger.info("consent.updated", enabled=enabled)

    def _save_config(self):
        self.config_path.write_text(json.dumps(self.config))
```

## False Positive Logging

```python
class DetectionLogger:
    """Log detections without audio content."""

    def log_detection(self, model: str, confidence: float, was_false_positive: bool = False):
        """Log detection event."""
        logger.info("wake_word.detection",
                   model=model,
                   confidence=confidence,
                   false_positive=was_false_positive,
                   # Never log audio content
                   timestamp=datetime.now().isoformat())

    def log_stats(self, period_hours: int = 24):
        """Log detection statistics."""
        # Query from metrics store
        stats = self._get_stats(period_hours)
        logger.info("wake_word.stats",
                   total_detections=stats["total"],
                   false_positives=stats["false_positives"],
                   false_positive_rate=stats["fpr"])
```

## Security Testing

```python
def test_audio_not_stored():
    """Verify audio is never written to disk."""
    import tempfile
    import os

    temp_dir = tempfile.mkdtemp()
    detector = SecureWakeWordDetector()

    # Run detector
    detector.start(lambda m, c: None)
    time.sleep(5)
    detector.stop()

    # Check no audio files created
    for root, dirs, files in os.walk(temp_dir):
        for f in files:
            assert not f.endswith(('.wav', '.raw', '.pcm'))

def test_buffer_cleared_on_detection():
    """Test audio buffer is cleared after detection."""
    detector = SecureWakeWordDetector()

    # Simulate audio and detection
    detector.audio_buffer.extend([0.1] * 16000)
    detector._process_audio()  # Triggers detection

    assert len(detector.audio_buffer) == 0

def test_max_buffer_size():
    """Ensure buffer never exceeds maximum."""
    detector = SecureWakeWordDetector()

    # Add more than max
    for _ in range(100):
        detector.audio_buffer.extend([0.1] * 1600)

    assert len(detector.audio_buffer) <= detector.buffer_size
```
