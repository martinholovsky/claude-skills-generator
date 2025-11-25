# GSAP Advanced Patterns

## Complex Timeline Orchestration

### Master Timeline with Labels

```typescript
export function createMasterTimeline(): gsap.core.Timeline {
  const master = gsap.timeline({ paused: true })

  master
    .add('intro')
    .add(createIntroSequence(), 'intro')
    .add('main', '+=0.5')
    .add(createMainSequence(), 'main')
    .add('outro', '+=1')
    .add(createOutroSequence(), 'outro')

  return master
}

// Jump to specific point
master.play('main')
master.tweenTo('outro', { duration: 0.5 })
```

## Custom Easing

### JARVIS-Style Easing

```typescript
// Register custom ease
gsap.registerEase('jarvisSnap', function(progress: number) {
  // Quick start, snappy finish
  return progress < 0.5
    ? 4 * progress * progress * progress
    : 1 - Math.pow(-2 * progress + 2, 3) / 2
})

// Usage
gsap.to(element, {
  x: 100,
  ease: 'jarvisSnap'
})
```

## Physics-Based Animation

### Spring Animation

```typescript
export function springTo(
  element: HTMLElement,
  props: gsap.TweenVars,
  config: { stiffness?: number; damping?: number } = {}
) {
  const { stiffness = 100, damping = 10 } = config

  return gsap.to(element, {
    ...props,
    ease: `elastic.out(${stiffness / 100}, ${damping / 100})`,
    duration: Math.sqrt(1 / (stiffness / 1000))
  })
}
```

## Morphing Paths

```typescript
import { MorphSVGPlugin } from 'gsap/MorphSVGPlugin'

gsap.registerPlugin(MorphSVGPlugin)

// Morph between shapes
gsap.to('#shape1', {
  morphSVG: '#shape2',
  duration: 1,
  ease: 'power2.inOut'
})
```

## Flip Animation

```typescript
import { Flip } from 'gsap/Flip'

gsap.registerPlugin(Flip)

export function flipLayout(items: HTMLElement[], newParent: HTMLElement) {
  // Record current state
  const state = Flip.getState(items)

  // Move items to new parent
  items.forEach(item => newParent.appendChild(item))

  // Animate the change
  return Flip.from(state, {
    duration: 0.5,
    ease: 'power2.inOut',
    stagger: 0.05
  })
}
```

## Performance Optimization

### Batch Updates

```typescript
// Batch multiple property changes
gsap.set(elements, {
  x: i => i * 10,
  y: i => i * 5,
  rotation: i => i * 15,
  immediateRender: true
})

// Use quickSetter for frequent updates
const setX = gsap.quickSetter(element, 'x', 'px')
const setY = gsap.quickSetter(element, 'y', 'px')

// In animation loop
function update(mouseX: number, mouseY: number) {
  setX(mouseX)
  setY(mouseY)
}
```
