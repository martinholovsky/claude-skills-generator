# Web Audio API Advanced Patterns

## AudioWorklet Processing

### Custom Audio Processor

```typescript
// audioWorklets/noiseGate.js
class NoiseGateProcessor extends AudioWorkletProcessor {
  static get parameterDescriptors() {
    return [
      {
        name: 'threshold',
        defaultValue: 0.01,
        minValue: 0,
        maxValue: 1
      }
    ]
  }

  process(inputs, outputs, parameters) {
    const input = inputs[0]
    const output = outputs[0]
    const threshold = parameters.threshold[0]

    for (let channel = 0; channel < input.length; channel++) {
      const inputChannel = input[channel]
      const outputChannel = output[channel]

      for (let i = 0; i < inputChannel.length; i++) {
        outputChannel[i] = Math.abs(inputChannel[i]) > threshold
          ? inputChannel[i]
          : 0
      }
    }

    return true
  }
}

registerProcessor('noise-gate', NoiseGateProcessor)
```

### Loading Worklet

```typescript
async function setupNoiseGate(ctx: AudioContext) {
  await ctx.audioWorklet.addModule('/audioWorklets/noiseGate.js')

  const noiseGate = new AudioWorkletNode(ctx, 'noise-gate')
  noiseGate.parameters.get('threshold').value = 0.05

  return noiseGate
}
```

## Voice Processing Pipeline

```typescript
export function createVoicePipeline(ctx: AudioContext) {
  // High-pass filter to remove rumble
  const highpass = ctx.createBiquadFilter()
  highpass.type = 'highpass'
  highpass.frequency.value = 80

  // Low-pass to remove hiss
  const lowpass = ctx.createBiquadFilter()
  lowpass.type = 'lowpass'
  lowpass.frequency.value = 8000

  // Compressor for consistent levels
  const compressor = ctx.createDynamicsCompressor()
  compressor.threshold.value = -24
  compressor.knee.value = 30
  compressor.ratio.value = 12
  compressor.attack.value = 0.003
  compressor.release.value = 0.25

  // Gain for final level
  const gain = ctx.createGain()
  gain.gain.value = 1.5

  // Connect chain
  highpass.connect(lowpass)
  lowpass.connect(compressor)
  compressor.connect(gain)

  return {
    input: highpass,
    output: gain
  }
}
```

## Convolution Reverb

```typescript
export async function createReverb(
  ctx: AudioContext,
  impulseUrl: string
) {
  const convolver = ctx.createConvolver()

  const response = await fetch(impulseUrl)
  const arrayBuffer = await response.arrayBuffer()
  convolver.buffer = await ctx.decodeAudioData(arrayBuffer)

  return convolver
}
```

## JARVIS Voice Synthesizer

```typescript
export function createJARVISVoice(ctx: AudioContext) {
  // Ring modulator for robotic effect
  const oscillator = ctx.createOscillator()
  oscillator.frequency.value = 50
  oscillator.type = 'sine'

  const ringMod = ctx.createGain()
  oscillator.connect(ringMod.gain)
  oscillator.start()

  // Vocoder-like effect
  const bandpass = ctx.createBiquadFilter()
  bandpass.type = 'bandpass'
  bandpass.frequency.value = 1000
  bandpass.Q.value = 5

  // Distortion for edge
  const waveshaper = ctx.createWaveShaper()
  const curve = new Float32Array(256)
  for (let i = 0; i < 256; i++) {
    const x = (i / 128) - 1
    curve[i] = Math.tanh(x * 2)
  }
  waveshaper.curve = curve

  // Connect
  ringMod.connect(bandpass)
  bandpass.connect(waveshaper)

  return {
    input: ringMod,
    output: waveshaper
  }
}
```

## Speech Recognition Integration

```typescript
export function useSpeechRecognition() {
  const recognition = ref<SpeechRecognition | null>(null)
  const transcript = ref('')
  const isListening = ref(false)

  function start() {
    const SpeechRecognition =
      window.SpeechRecognition || window.webkitSpeechRecognition

    if (!SpeechRecognition) {
      throw new Error('Speech recognition not supported')
    }

    recognition.value = new SpeechRecognition()
    recognition.value.continuous = true
    recognition.value.interimResults = true

    recognition.value.onresult = (event) => {
      let final = ''
      for (let i = 0; i < event.results.length; i++) {
        if (event.results[i].isFinal) {
          final += event.results[i][0].transcript
        }
      }
      transcript.value = final
    }

    recognition.value.start()
    isListening.value = true
  }

  function stop() {
    recognition.value?.stop()
    isListening.value = false
  }

  return { transcript, isListening, start, stop }
}
```
