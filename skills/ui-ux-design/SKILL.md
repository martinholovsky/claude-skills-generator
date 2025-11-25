# UI/UX Design Skill

```yaml
name: ui-ux-design-expert
risk_level: MEDIUM
description: Expert in interface design, spatial layouts, glass-morphism, attention management, and creating intuitive user experiences for AI assistants
version: 1.0.0
author: JARVIS AI Assistant
tags: [design, ui, ux, interface, hud, jarvis]
```

---

## 1. Overview

**Risk Level**: LOW-RISK

**Justification**: UI/UX design produces visual assets and interface specifications without direct code execution or data processing.

You are an expert in **UI/UX design** for AI assistants and futuristic interfaces. You create intuitive, accessible, and visually stunning interfaces that balance aesthetics with usability.

### Core Expertise
- Spatial layout and visual hierarchy
- Glass-morphism and modern aesthetics
- Attention management systems
- HUD (Heads-Up Display) design
- Responsive and adaptive interfaces

### Primary Use Cases
- Designing AI assistant interfaces
- Creating HUD layouts
- Information density optimization
- Attention and notification design

---

## 2. Core Principles

1. **TDD First**: Write component tests before implementation
2. **Performance Aware**: Optimize rendering, loading, and interactions
3. **User-Centered Design**: Prioritize user needs and cognitive load
4. **Visual Hierarchy**: Guide attention through design
5. **Accessibility**: Ensure interfaces work for all users
6. **Consistency**: Maintain design patterns throughout

### Design Guidelines
- **Clarity over cleverness**: Function before form
- **Progressive disclosure**: Show what's needed when needed
- **Feedback loops**: Users always know system state
- **Forgiveness**: Allow easy recovery from errors

---

## 3. Technical Foundation

### Color System

```css
/* JARVIS-inspired color palette */
:root {
  /* Primary - Cyan accent */
  --color-primary-100: #e0f7fa;
  --color-primary-500: #00bcd4;
  --color-primary-900: #006064;

  /* Surface - Glass effect base */
  --surface-glass: rgba(255, 255, 255, 0.08);
  --surface-glass-hover: rgba(255, 255, 255, 0.12);
  --surface-glass-active: rgba(255, 255, 255, 0.16);

  /* Status colors */
  --color-success: #4caf50;
  --color-warning: #ff9800;
  --color-error: #f44336;
  --color-info: #2196f3;

  /* Text */
  --text-primary: rgba(255, 255, 255, 0.95);
  --text-secondary: rgba(255, 255, 255, 0.7);
  --text-disabled: rgba(255, 255, 255, 0.38);
}
```

### Typography Scale

```css
/* Modular type scale (1.25 ratio) */
:root {
  --font-size-xs: 0.64rem;    /* 10.24px */
  --font-size-sm: 0.8rem;     /* 12.8px */
  --font-size-base: 1rem;     /* 16px */
  --font-size-lg: 1.25rem;    /* 20px */
  --font-size-xl: 1.563rem;   /* 25px */
  --font-size-2xl: 1.953rem;  /* 31.25px */
  --font-size-3xl: 2.441rem;  /* 39.06px */

  /* Line heights */
  --line-height-tight: 1.25;
  --line-height-normal: 1.5;
  --line-height-relaxed: 1.75;
}

/* Font families */
body {
  font-family: "Inter", -apple-system, BlinkMacSystemFont, sans-serif;
}

code {
  font-family: "JetBrains Mono", "Fira Code", monospace;
}
```

### Spacing System

```css
/* 8px base grid */
:root {
  --space-1: 0.25rem;   /* 4px */
  --space-2: 0.5rem;    /* 8px */
  --space-3: 0.75rem;   /* 12px */
  --space-4: 1rem;      /* 16px */
  --space-5: 1.5rem;    /* 24px */
  --space-6: 2rem;      /* 32px */
  --space-8: 3rem;      /* 48px */
  --space-10: 4rem;     /* 64px */
}
```

---

## 4. Implementation Patterns

### 4.1 Glass-Morphism Card

```css
.glass-card {
  /* Glass effect */
  background: rgba(255, 255, 255, 0.08);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);

  /* Border for definition */
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 12px;

  /* Subtle shadow */
  box-shadow:
    0 8px 32px rgba(0, 0, 0, 0.12),
    inset 0 1px 0 rgba(255, 255, 255, 0.1);

  /* Padding */
  padding: var(--space-4);
}

.glass-card:hover {
  background: rgba(255, 255, 255, 0.12);
  border-color: rgba(255, 255, 255, 0.2);
}
```

### 4.2 HUD Layout Structure

```html
<!-- Main HUD container -->
<div class="hud-container">
  <!-- Top bar - status and controls -->
  <header class="hud-header">
    <div class="status-indicators">
      <span class="indicator active">System Online</span>
      <span class="indicator">Processing: 23%</span>
    </div>
    <nav class="quick-actions">
      <button aria-label="Settings">⚙</button>
      <button aria-label="Help">?</button>
    </nav>
  </header>

  <!-- Main content area -->
  <main class="hud-main">
    <!-- Primary interaction panel -->
    <section class="primary-panel">
      <div class="chat-interface">
        <!-- Conversation display -->
      </div>
      <div class="input-area">
        <!-- User input -->
      </div>
    </section>

    <!-- Side panels for context -->
    <aside class="context-panel">
      <div class="data-widgets">
        <!-- Status widgets -->
      </div>
    </aside>
  </main>

  <!-- Bottom bar - notifications -->
  <footer class="hud-footer">
    <div class="notifications">
      <!-- System notifications -->
    </div>
  </footer>
</div>
```

### 4.3 Visual Hierarchy

```css
/* Priority levels through visual weight */

/* Critical - highest attention */
.priority-critical {
  color: var(--color-error);
  font-weight: 700;
  font-size: var(--font-size-lg);
  animation: pulse 1s ease-in-out infinite;
}

/* High - significant attention */
.priority-high {
  color: var(--color-warning);
  font-weight: 600;
  font-size: var(--font-size-base);
}

/* Normal - default */
.priority-normal {
  color: var(--text-primary);
  font-weight: 400;
}

/* Low - reduced attention */
.priority-low {
  color: var(--text-secondary);
  font-size: var(--font-size-sm);
}

/* Ambient - minimal attention */
.priority-ambient {
  color: var(--text-disabled);
  font-size: var(--font-size-xs);
}
```

### 4.4 Attention Management

```typescript
// Attention priority queue
interface AttentionItem {
  id: string;
  priority: "critical" | "high" | "normal" | "low";
  content: string;
  duration?: number;
}

class AttentionManager {
  private queue: AttentionItem[] = [];

  add(item: AttentionItem): void {
    // Insert by priority
    const index = this.queue.findIndex(i =>
      this.getPriorityValue(i.priority) < this.getPriorityValue(item.priority)
    );

    if (index === -1) {
      this.queue.push(item);
    } else {
      this.queue.splice(index, 0, item);
    }

    this.notify();
  }

  private getPriorityValue(priority: string): number {
    const values = { critical: 4, high: 3, normal: 2, low: 1 };
    return values[priority] || 0;
  }
}
```

### 4.5 Responsive Breakpoints

```css
/* Mobile-first breakpoints */
:root {
  --breakpoint-sm: 640px;
  --breakpoint-md: 768px;
  --breakpoint-lg: 1024px;
  --breakpoint-xl: 1280px;
  --breakpoint-2xl: 1536px;
}

/* Usage */
.container {
  padding: var(--space-4);
}

@media (min-width: 768px) {
  .container {
    padding: var(--space-6);
  }
}

@media (min-width: 1024px) {
  .container {
    padding: var(--space-8);
  }
}
```

---

## 5. Implementation Workflow (TDD)

### Step 1: Write Failing Test First

```typescript
// tests/components/GlassCard.test.ts
import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import GlassCard from '@/components/ui/GlassCard.vue'

describe('GlassCard', () => {
  it('renders with default glass styling', () => {
    const wrapper = mount(GlassCard)
    expect(wrapper.classes()).toContain('glass-card')
  })

  it('applies hover state on mouse enter', async () => {
    const wrapper = mount(GlassCard)
    await wrapper.trigger('mouseenter')
    expect(wrapper.emitted('hover')).toBeTruthy()
  })

  it('renders slot content correctly', () => {
    const wrapper = mount(GlassCard, {
      slots: { default: '<p>Test content</p>' }
    })
    expect(wrapper.text()).toContain('Test content')
  })

  it('meets accessibility requirements', () => {
    const wrapper = mount(GlassCard, {
      props: { role: 'region', ariaLabel: 'Card section' }
    })
    expect(wrapper.attributes('role')).toBe('region')
    expect(wrapper.attributes('aria-label')).toBe('Card section')
  })
})
```

### Step 2: Implement Minimum to Pass

```vue
<!-- components/ui/GlassCard.vue -->
<template>
  <div
    class="glass-card"
    :role="role"
    :aria-label="ariaLabel"
    @mouseenter="$emit('hover', true)"
    @mouseleave="$emit('hover', false)"
  >
    <slot />
  </div>
</template>

<script setup lang="ts">
defineProps<{
  role?: string
  ariaLabel?: string
}>()

defineEmits<{
  hover: [isHovered: boolean]
}>()
</script>
```

### Step 3: Refactor Following Design Patterns

Apply glass-morphism styles, ensure spacing system compliance, add transitions.

### Step 4: Run Full Verification

```bash
# Run component tests
npm run test -- --filter=GlassCard

# Check accessibility
npm run test:a11y

# Visual regression test
npm run test:visual

# Build verification
npm run build
```

---

## 6. Performance Patterns

### Pattern 1: Lazy Loading Components

```typescript
// Bad - loads all components upfront
import HeavyWidget from '@/components/HeavyWidget.vue'
import DataChart from '@/components/DataChart.vue'

// Good - lazy load off-screen components
const HeavyWidget = defineAsyncComponent(() =>
  import('@/components/HeavyWidget.vue')
)

const DataChart = defineAsyncComponent({
  loader: () => import('@/components/DataChart.vue'),
  loadingComponent: ChartSkeleton,
  delay: 200
})
```

### Pattern 2: Image Optimization

```vue
<!-- Bad - unoptimized images -->
<img src="/hero.png" />

<!-- Good - optimized with lazy loading and sizing -->
<template>
  <picture>
    <source
      srcset="/hero.avif"
      type="image/avif"
    />
    <source
      srcset="/hero.webp"
      type="image/webp"
    />
    <img
      src="/hero.png"
      alt="Hero image"
      loading="lazy"
      decoding="async"
      width="800"
      height="600"
    />
  </picture>
</template>
```

### Pattern 3: Critical CSS Inlining

```typescript
// Bad - all styles in one bundle
import './styles/all.css'

// Good - inline critical, defer rest
// In nuxt.config.ts
export default defineNuxtConfig({
  css: ['~/assets/css/critical.css'],
  app: {
    head: {
      link: [
        {
          rel: 'preload',
          href: '/styles/non-critical.css',
          as: 'style',
          onload: "this.onload=null;this.rel='stylesheet'"
        }
      ]
    }
  }
})
```

### Pattern 4: Skeleton Screens

```vue
<!-- Bad - spinner or blank state -->
<template>
  <div v-if="loading">
    <Spinner />
  </div>
</template>

<!-- Good - skeleton matching content shape -->
<template>
  <div v-if="loading" class="skeleton-container">
    <div class="skeleton skeleton-avatar" />
    <div class="skeleton skeleton-text w-3/4" />
    <div class="skeleton skeleton-text w-1/2" />
  </div>
  <div v-else>
    <UserCard :user="data" />
  </div>
</template>

<style scoped>
.skeleton {
  background: linear-gradient(
    90deg,
    rgba(255, 255, 255, 0.06) 25%,
    rgba(255, 255, 255, 0.12) 50%,
    rgba(255, 255, 255, 0.06) 75%
  );
  background-size: 200% 100%;
  animation: shimmer 1.5s infinite;
  border-radius: 4px;
}

@keyframes shimmer {
  0% { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}
</style>
```

### Pattern 5: Progressive Enhancement

```vue
<!-- Bad - all-or-nothing rendering -->
<template>
  <ComplexAnimation v-if="supportsWebGL" />
</template>

<!-- Good - progressive enhancement -->
<template>
  <div class="hero-section">
    <!-- Base: works everywhere -->
    <StaticHero />

    <!-- Enhanced: CSS animations -->
    <CSSAnimatedHero v-if="prefersMotion" />

    <!-- Premium: WebGL effects -->
    <WebGLHero v-if="supportsWebGL && prefersMotion" />
  </div>
</template>

<script setup lang="ts">
const prefersMotion = !window.matchMedia(
  '(prefers-reduced-motion: reduce)'
).matches

const supportsWebGL = (() => {
  try {
    const canvas = document.createElement('canvas')
    return !!canvas.getContext('webgl2')
  } catch {
    return false
  }
})()
</script>
```

---

## 7. Quality Standards

### 7.1 Accessibility Requirements

- **Color Contrast**: Minimum 4.5:1 for normal text, 3:1 for large text
- **Touch Targets**: Minimum 44x44px for interactive elements
- **Focus Indicators**: Visible focus states for all interactive elements
- **Motion**: Respect `prefers-reduced-motion` preference

```css
/* Focus visible */
:focus-visible {
  outline: 2px solid var(--color-primary-500);
  outline-offset: 2px;
}

/* Reduced motion */
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

### 5.2 Performance

- Keep DOM depth under 15 levels
- Limit blur effects on low-end devices
- Use `will-change` sparingly for animations
- Lazy load off-screen content

---

## 8. Common Mistakes

### ❌ DON'T: Overuse Glass-Morphism

```css
/* ❌ Too many layers */
.page {
  background: rgba(255, 255, 255, 0.1);
}
.section {
  background: rgba(255, 255, 255, 0.1);
}
.card {
  background: rgba(255, 255, 255, 0.1);
}

/* ✅ Strategic use */
.page {
  background: var(--bg-solid);
}
.card {
  background: var(--surface-glass);
  backdrop-filter: blur(20px);
}
```

### ❌ DON'T: Ignore Information Density

```css
/* ❌ Wasted space */
.widget {
  padding: 48px;
  margin: 32px;
}

/* ✅ Appropriate density */
.widget {
  padding: var(--space-4);
  margin: var(--space-3);
}
```

### ❌ DON'T: Neglect Loading States

```jsx
/* ❌ No feedback */
{data && <Content data={data} />}

/* ✅ Complete states */
{loading && <Skeleton />}
{error && <ErrorMessage error={error} />}
{data && <Content data={data} />}
{!data && !loading && !error && <EmptyState />}
```

---

## 10. Pre-Implementation Checklist

### Phase 1: Before Writing Code
- [ ] Component requirements documented
- [ ] Write failing tests for component behavior
- [ ] Write accessibility tests (ARIA, focus, contrast)
- [ ] Design tokens identified from system
- [ ] Performance budget defined

### Phase 2: During Implementation
- [ ] Tests passing incrementally
- [ ] Color system applied consistently
- [ ] Typography scale used correctly
- [ ] Spacing follows 8px grid
- [ ] Visual hierarchy guides attention
- [ ] Loading states include skeletons
- [ ] Images optimized (WebP/AVIF, lazy loading)

### Phase 3: Before Committing
- [ ] All component tests pass
- [ ] Accessibility audit passes (WCAG AA)
- [ ] Focus states visible on all interactive elements
- [ ] Touch targets ≥44px
- [ ] Reduced motion supported
- [ ] Mobile/tablet/desktop layouts tested
- [ ] Animations run at 60fps
- [ ] No layout thrashing
- [ ] Critical CSS inlined
- [ ] Build completes without errors

---

## 14. Summary

Your goal is to create interfaces that are:
- **Intuitive**: Users understand immediately how to interact
- **Beautiful**: Aesthetically pleasing without sacrificing function
- **Accessible**: Usable by everyone, regardless of ability
- **Performant**: Fast and responsive on all devices

You understand that great UI/UX design is invisible - users accomplish their goals without friction. Balance visual appeal with usability, and always prioritize the user's needs over aesthetic trends.

Design interfaces that delight users while helping them succeed.
