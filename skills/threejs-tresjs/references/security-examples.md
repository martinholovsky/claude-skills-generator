# Three.js/TresJS Security Examples

## ReDoS Prevention

### Safe Color Input

```typescript
// Regex that caused ReDoS in Three.js < 0.125.0
// was in Color.setStyle() for rgb/hsl parsing

// ✅ Safe color validation
const COLOR_PATTERNS = {
  hex3: /^#[0-9a-fA-F]{3}$/,
  hex6: /^#[0-9a-fA-F]{6}$/,
  rgb: /^rgb\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)$/,
  hsl: /^hsl\(\s*(\d{1,3})\s*,\s*(\d{1,3})%\s*,\s*(\d{1,3})%\s*\)$/
}

export function validateColorInput(input: string): boolean {
  return Object.values(COLOR_PATTERNS).some(pattern => pattern.test(input))
}

export function safeColorFromString(input: string, fallback = '#00ff41'): Color {
  if (!validateColorInput(input)) {
    console.warn(`Invalid color: ${input}, using fallback`)
    return new Color(fallback)
  }
  return new Color(input)
}
```

## Memory Leak Prevention

### Complete Disposal Pattern

```typescript
export function disposeObject(object: Object3D): void {
  object.traverse((child) => {
    if (child instanceof Mesh) {
      // Dispose geometry
      child.geometry.dispose()

      // Dispose materials
      const materials = Array.isArray(child.material)
        ? child.material
        : [child.material]

      materials.forEach((material) => {
        // Dispose textures
        Object.values(material).forEach((value) => {
          if (value instanceof Texture) {
            value.dispose()
          }
        })
        material.dispose()
      })
    }
  })
}
```

## Frame Rate Protection

### GPU Timeout Detection

```typescript
export function useGPUTimeout(maxFrameTime = 100) {
  let lastFrameTime = performance.now()
  let consecutiveLongFrames = 0

  return {
    checkFrame(): boolean {
      const now = performance.now()
      const frameTime = now - lastFrameTime
      lastFrameTime = now

      if (frameTime > maxFrameTime) {
        consecutiveLongFrames++
        if (consecutiveLongFrames > 5) {
          console.error('GPU performance issue detected')
          return false
        }
      } else {
        consecutiveLongFrames = 0
      }
      return true
    }
  }
}
```
