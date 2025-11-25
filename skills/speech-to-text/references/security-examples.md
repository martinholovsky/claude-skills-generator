# Speech-to-Text Security Examples

## Audio Data Security

### Secure Temporary File Handling

```python
import os
import tempfile
from pathlib import Path
from cryptography.fernet import Fernet

class SecureAudioStorage:
    """Secure temporary storage for audio files."""

    def __init__(self):
        # Create restricted temp directory
        self.temp_dir = tempfile.mkdtemp(prefix="jarvis_stt_")
        os.chmod(self.temp_dir, 0o700)

        # Generate encryption key
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def store_audio(self, audio_data: bytes) -> str:
        """Store audio encrypted."""
        encrypted = self.cipher.encrypt(audio_data)
        path = Path(self.temp_dir) / f"{uuid.uuid4()}.enc"
        path.write_bytes(encrypted)
        return str(path)

    def retrieve_audio(self, path: str) -> bytes:
        """Retrieve and decrypt audio."""
        encrypted = Path(path).read_bytes()
        return self.cipher.decrypt(encrypted)

    def delete_audio(self, path: str):
        """Securely delete audio file."""
        p = Path(path)
        if p.exists():
            # Overwrite with zeros before deletion
            size = p.stat().st_size
            p.write_bytes(b'\x00' * size)
            p.unlink()

    def cleanup(self):
        """Clean up all temp files."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
```

### Privacy-Preserving Logging

```python
import hashlib
import structlog

logger = structlog.get_logger()

class PrivacyLogger:
    """Log STT events without exposing content."""

    @staticmethod
    def log_transcription(text: str, duration: float, language: str):
        """Log transcription metadata only."""
        # Hash content for debugging without exposure
        content_hash = hashlib.sha256(text.encode()).hexdigest()[:16]

        logger.info("stt.transcribed",
                   word_count=len(text.split()),
                   char_count=len(text),
                   duration=duration,
                   language=language,
                   content_hash=content_hash)  # For debugging only

    @staticmethod
    def log_error(error: Exception, audio_path: str):
        """Log error without exposing file content."""
        logger.error("stt.error",
                    error_type=type(error).__name__,
                    # Never log actual file path with user data
                    file_size=Path(audio_path).stat().st_size if Path(audio_path).exists() else 0)
```

### Input Validation

```python
import magic
import soundfile as sf

class AudioValidator:
    """Validate audio files for security."""

    MAX_SIZE = 50 * 1024 * 1024  # 50MB
    MAX_DURATION = 300  # 5 minutes
    ALLOWED_FORMATS = {'audio/wav', 'audio/x-wav', 'audio/mpeg', 'audio/flac'}

    def validate(self, path: str) -> bool:
        p = Path(path)

        # Check exists
        if not p.exists():
            raise ValidationError("File not found")

        # Check size
        if p.stat().st_size > self.MAX_SIZE:
            raise ValidationError(f"File too large: {p.stat().st_size}")

        # Check MIME type by content (not extension)
        mime = magic.from_file(path, mime=True)
        if mime not in self.ALLOWED_FORMATS:
            raise ValidationError(f"Invalid format: {mime}")

        # Check audio properties
        try:
            info = sf.info(path)
            if info.duration > self.MAX_DURATION:
                raise ValidationError(f"Audio too long: {info.duration}s")
        except Exception as e:
            raise ValidationError(f"Invalid audio: {e}")

        return True
```

## Security Testing

```python
def test_audio_deleted_after_transcription():
    """Ensure audio is deleted after processing."""
    audio_path = create_test_audio()
    assert Path(audio_path).exists()

    engine.transcribe(audio_path)

    assert not Path(audio_path).exists()

def test_no_pii_in_logs(caplog):
    """Ensure transcription content not logged."""
    engine.transcribe(create_audio_with_pii())

    for record in caplog.records:
        assert "555-123-4567" not in record.message  # Phone
        assert "test@example.com" not in record.message  # Email

def test_pii_filtered():
    """Test PII is removed from transcription."""
    # Audio saying "Call me at 555-123-4567"
    result = privacy_stt.transcribe_private(audio_with_phone)

    assert "555-123-4567" not in result["text"]
    assert "[PHONE]" in result["text"]
```
