# Speech-to-Text Advanced Patterns

## GPU Optimization

```python
class GPUOptimizedSTT:
    """GPU-optimized Faster Whisper setup."""

    def __init__(self, model_size: str = "medium"):
        import torch

        # Select best compute type for GPU
        if torch.cuda.is_available():
            device = "cuda"
            compute_type = "float16"  # Best for GPU
        else:
            device = "cpu"
            compute_type = "int8"  # Best for CPU

        self.model = WhisperModel(
            model_size,
            device=device,
            compute_type=compute_type,
            num_workers=4
        )

        logger.info("stt.gpu_init",
                   device=device,
                   compute_type=compute_type)
```

## Batch Processing

```python
from concurrent.futures import ThreadPoolExecutor

class BatchSTT:
    """Process multiple audio files efficiently."""

    def __init__(self, engine: SecureSTTEngine, max_workers: int = 4):
        self.engine = engine
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    def transcribe_batch(self, audio_paths: list[str]) -> list[str]:
        """Transcribe multiple files in parallel."""
        futures = [
            self.executor.submit(self.engine.transcribe, path)
            for path in audio_paths
        ]

        return [f.result() for f in futures]
```

## Language Detection

```python
class MultiLanguageSTT:
    """Handle multiple languages."""

    def __init__(self, engine: SecureSTTEngine):
        self.engine = engine

    def transcribe_auto(self, audio_path: str) -> dict:
        """Transcribe with automatic language detection."""
        segments, info = self.engine.model.transcribe(
            audio_path,
            language=None  # Auto-detect
        )

        text = " ".join(s.text for s in segments)

        return {
            "text": text,
            "language": info.language,
            "language_probability": info.language_probability
        }
```

## Voice Activity Detection

```python
import webrtcvad
import wave

class VADProcessor:
    """Voice activity detection for better segmentation."""

    def __init__(self, aggressiveness: int = 3):
        self.vad = webrtcvad.Vad(aggressiveness)

    def extract_speech(self, audio_path: str) -> list[tuple]:
        """Extract speech segments from audio."""
        with wave.open(audio_path, 'rb') as wf:
            sample_rate = wf.getframerate()
            frames = wf.readframes(wf.getnframes())

        # Process in 30ms frames
        frame_duration = 30  # ms
        frame_size = int(sample_rate * frame_duration / 1000) * 2

        speech_segments = []
        current_segment = []

        for i in range(0, len(frames), frame_size):
            frame = frames[i:i+frame_size]
            if len(frame) < frame_size:
                break

            is_speech = self.vad.is_speech(frame, sample_rate)
            if is_speech:
                current_segment.append(frame)
            elif current_segment:
                speech_segments.append(b''.join(current_segment))
                current_segment = []

        return speech_segments
```

## Model Selection Strategy

```python
def select_model(
    hardware: str,
    latency_requirement: str,
    accuracy_requirement: str
) -> str:
    """Select optimal model based on requirements."""

    if hardware == "gpu" and accuracy_requirement == "high":
        return "large-v3"
    elif hardware == "gpu":
        return "medium"
    elif latency_requirement == "low":
        return "tiny"
    elif accuracy_requirement == "high":
        return "small"
    else:
        return "base"
```

## Streaming with WebSocket

```python
from fastapi import WebSocket

class WebSocketSTT:
    """Real-time STT over WebSocket."""

    def __init__(self, engine: SecureSTTEngine):
        self.engine = engine

    async def handle_stream(self, websocket: WebSocket):
        await websocket.accept()

        audio_buffer = []

        try:
            while True:
                data = await websocket.receive_bytes()
                audio_buffer.append(data)

                # Process when we have enough data
                if len(audio_buffer) >= 10:  # ~2.5 seconds
                    audio = b''.join(audio_buffer)
                    text = await self._transcribe_chunk(audio)

                    if text.strip():
                        await websocket.send_text(text)

                    audio_buffer = []

        except Exception as e:
            logger.error("websocket.error", error=str(e))
        finally:
            await websocket.close()
```
