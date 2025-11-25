# Text-to-Speech Security Examples

## Content Filtering Implementation

```python
import re
from typing import Tuple

class TTSContentFilter:
    """Comprehensive content filtering for TTS."""

    SENSITIVE_PATTERNS = [
        r"password\s*[:=]\s*\S+",
        r"api[_-]?key\s*[:=]\s*\S+",
        r"secret\s*[:=]\s*\S+",
        r"token\s*[:=]\s*\S+",
        r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  # Phone
        r"\b\d{16}\b",  # Credit card
    ]

    def filter(self, text: str) -> Tuple[str, list]:
        """Filter sensitive content, return (filtered_text, warnings)."""
        warnings = []

        for pattern in self.SENSITIVE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                text = re.sub(pattern, "[FILTERED]", text, flags=re.IGNORECASE)
                warnings.append(f"Filtered pattern: {pattern[:20]}")

        return text, warnings

# Usage
filter = TTSContentFilter()
filtered, warnings = filter.filter("Password is abc123")
assert "abc123" not in filtered
```

## Resource Exhaustion Prevention

```python
class RateLimitedTTS:
    """Prevent DoS via synthesis abuse."""

    def __init__(self, max_chars_per_minute: int = 10000):
        self.max_chars = max_chars_per_minute
        self.usage = []

    def check_limit(self, text: str) -> bool:
        now = time.time()
        minute_ago = now - 60

        # Remove old entries
        self.usage = [(t, c) for t, c in self.usage if t > minute_ago]

        # Check current usage
        current = sum(c for _, c in self.usage)
        if current + len(text) > self.max_chars:
            raise RateLimitError("TTS rate limit exceeded")

        self.usage.append((now, len(text)))
        return True
```

## Secure Audio File Handling

```python
import os
from pathlib import Path

class SecureAudioOutput:
    """Secure handling of generated audio."""

    def save_audio(self, audio: np.ndarray, sample_rate: int) -> str:
        """Save audio with secure permissions."""
        path = Path(tempfile.mktemp(suffix='.wav'))

        # Save audio
        sf.write(str(path), audio, sample_rate)

        # Set restrictive permissions
        os.chmod(path, 0o600)

        return str(path)

    def cleanup(self, path: str):
        """Securely delete audio file."""
        p = Path(path)
        if p.exists():
            # Overwrite before deletion
            size = p.stat().st_size
            p.write_bytes(b'\x00' * size)
            p.unlink()
```

## Security Testing

```python
def test_sensitive_content_filtered():
    """Test that sensitive content is filtered."""
    test_cases = [
        ("Password: secret123", "secret123"),
        ("API key is abc123xyz", "abc123xyz"),
        ("Call 555-123-4567", "555-123-4567"),
    ]

    filter = TTSContentFilter()
    for text, sensitive in test_cases:
        filtered, _ = filter.filter(text)
        assert sensitive not in filtered

def test_text_length_limit():
    """Test that long text is rejected."""
    engine = SecureTTSEngine()
    long_text = "x" * 6000

    with pytest.raises(ValidationError):
        engine.synthesize(long_text)

def test_audio_deleted_after_use():
    """Test audio cleanup."""
    path = engine.synthesize("Hello")
    assert Path(path).exists()

    cleanup_audio(path)
    assert not Path(path).exists()
```
