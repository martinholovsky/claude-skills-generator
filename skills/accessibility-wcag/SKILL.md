# Accessibility & WCAG Compliance Skill

```yaml
name: accessibility-wcag-expert
risk_level: HIGH
description: Expert in WCAG 2.2 guidelines, keyboard navigation, screen reader support, and creating fully accessible interfaces
version: 1.0.0
author: JARVIS AI Assistant
tags: [accessibility, wcag, a11y, screen-reader, keyboard]
```

---

## 1. Overview

**Risk Level**: LOW-RISK

**Justification**: Accessibility work produces semantic HTML, ARIA attributes, and CSS without direct code execution or data processing.

You are an expert in **web accessibility** and WCAG compliance. You create inclusive interfaces that work for everyone, regardless of ability, device, or assistive technology.

### Core Principles

1. **TDD First** - Write accessibility tests before implementation
2. **Performance Aware** - Optimize for assistive technology efficiency
3. **POUR Compliance** - Perceivable, Operable, Understandable, Robust
4. **Progressive Enhancement** - Works without JavaScript first

### Core Expertise
- WCAG 2.2 Level AA compliance
- Keyboard navigation
- Screen reader optimization
- Color and contrast requirements
- Focus management

### Primary Use Cases
- Auditing interfaces for accessibility
- Implementing accessible components
- Screen reader compatibility
- Keyboard-only navigation

---

## 2. Implementation Workflow (TDD)

### Step 1: Write Failing Accessibility Test First

```typescript
// tests/components/button.a11y.test.ts
import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/vue'
import { axe, toHaveNoViolations } from 'jest-axe'
import ActionButton from '@/components/ActionButton.vue'

expect.extend(toHaveNoViolations)

describe('ActionButton Accessibility', () => {
  it('should have no accessibility violations', async () => {
    const { container } = render(ActionButton, {
      props: { label: 'Submit Form' }
    })

    const results = await axe(container)
    expect(results).toHaveNoViolations()
  })

  it('should have accessible name', async () => {
    const { getByRole } = render(ActionButton, {
      props: { label: 'Submit Form' }
    })

    const button = getByRole('button', { name: 'Submit Form' })
    expect(button).toBeTruthy()
  })

  it('should be keyboard focusable', async () => {
    const { getByRole } = render(ActionButton, {
      props: { label: 'Submit' }
    })

    const button = getByRole('button')
    button.focus()
    expect(document.activeElement).toBe(button)
  })

  it('should announce state changes to screen readers', async () => {
    const { getByRole } = render(ActionButton, {
      props: { label: 'Submit', loading: true }
    })

    const button = getByRole('button')
    expect(button).toHaveAttribute('aria-busy', 'true')
  })
})
```

### Step 2: Implement Minimum to Pass

```vue
<!-- components/ActionButton.vue -->
<template>
  <button
    :aria-busy="loading"
    :aria-disabled="disabled"
    :disabled="disabled || loading"
    class="action-button"
  >
    <span v-if="loading" aria-hidden="true" class="spinner" />
    <span :class="{ 'visually-hidden': loading && hideTextWhenLoading }">
      {{ label }}
    </span>
  </button>
</template>

<script setup lang="ts">
defineProps<{
  label: string
  loading?: boolean
  disabled?: boolean
  hideTextWhenLoading?: boolean
}>()
</script>
```

### Step 3: Refactor Following WCAG Patterns

Add enhanced focus styles, proper contrast, and ARIA improvements.

### Step 4: Run Full Accessibility Verification

```bash
# Run accessibility tests
npm run test -- --grep "a11y"

# Run axe-core audit
npx axe --dir ./dist

# Check with Lighthouse
npx lighthouse http://localhost:3000 --only-categories=accessibility
```

---

## 3. Performance Patterns

### Pattern 1: Semantic HTML Over ARIA

```html
<!-- Bad: Excessive ARIA recreating native semantics -->
<div role="button" tabindex="0" aria-pressed="false" onclick="toggle()">
  Toggle
</div>

<!-- Good: Native HTML with automatic accessibility -->
<button type="button" aria-pressed="false" onclick="toggle()">
  Toggle
</button>
```

### Pattern 2: Efficient ARIA Updates

```typescript
// Bad: Updating entire live region on each change
function updateStatus(message: string) {
  liveRegion.innerHTML = `
    <div role="status">
      <span>${timestamp}</span>
      <span>${message}</span>
      <span>${context}</span>
    </div>
  `
}

// Good: Minimal updates to live regions
function updateStatus(message: string) {
  // Only update the text content, not structure
  statusText.textContent = message
}
```

### Pattern 3: Optimized Focus Management

```typescript
// Bad: Searching DOM repeatedly
function trapFocus(element: HTMLElement) {
  document.addEventListener('keydown', (e) => {
    // Queries DOM on every keypress
    const focusable = element.querySelectorAll('button, [href], input')
    // ...
  })
}

// Good: Cache focusable elements
function trapFocus(element: HTMLElement) {
  const focusable = element.querySelectorAll<HTMLElement>(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
  )
  const firstFocusable = focusable[0]
  const lastFocusable = focusable[focusable.length - 1]

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key !== 'Tab') return

    if (e.shiftKey && document.activeElement === firstFocusable) {
      e.preventDefault()
      lastFocusable.focus()
    } else if (!e.shiftKey && document.activeElement === lastFocusable) {
      e.preventDefault()
      firstFocusable.focus()
    }
  }

  element.addEventListener('keydown', handleKeyDown)
  return () => element.removeEventListener('keydown', handleKeyDown)
}
```

### Pattern 4: Reduced Motion Support

```css
/* Bad: Animations without motion preference check */
.animated-element {
  animation: slide-in 0.5s ease-out;
}

/* Good: Respect user motion preferences */
.animated-element {
  animation: slide-in 0.5s ease-out;
}

@media (prefers-reduced-motion: reduce) {
  .animated-element {
    animation: none;
    transition: none;
  }
}
```

```typescript
// JavaScript motion preference detection
const prefersReducedMotion = window.matchMedia(
  '(prefers-reduced-motion: reduce)'
).matches

function animate(element: HTMLElement) {
  if (prefersReducedMotion) {
    // Instant state change, no animation
    element.style.opacity = '1'
    return
  }

  // Full animation for users who prefer it
  element.animate([
    { opacity: 0 },
    { opacity: 1 }
  ], { duration: 300 })
}
```

### Pattern 5: Lazy Loading for Screen Readers

```html
<!-- Bad: Loading all content, overwhelming screen readers -->
<div class="content">
  <!-- 100+ items all loaded at once -->
</div>

<!-- Good: Progressive disclosure with proper announcements -->
<div class="content" role="feed" aria-busy="false">
  <article aria-posinset="1" aria-setsize="100">...</article>
  <article aria-posinset="2" aria-setsize="100">...</article>
  <!-- Load more on scroll/request -->
</div>

<div role="status" aria-live="polite" class="visually-hidden">
  <!-- Announce when new content loads -->
  Loaded 10 more items
</div>
```

```typescript
// Efficient lazy loading with accessibility
function loadMoreContent() {
  const liveRegion = document.querySelector('[role="status"]')
  const feed = document.querySelector('[role="feed"]')

  // Mark as loading
  feed?.setAttribute('aria-busy', 'true')

  // Load content
  const newItems = await fetchItems()

  // Append without reflow
  const fragment = document.createDocumentFragment()
  newItems.forEach(item => fragment.appendChild(createArticle(item)))
  feed?.appendChild(fragment)

  // Mark complete and announce
  feed?.setAttribute('aria-busy', 'false')
  if (liveRegion) {
    liveRegion.textContent = `Loaded ${newItems.length} more items`
  }
}
```

---

## 4. Core Responsibilities

### Fundamental Duties
1. **POUR Principles**: Perceivable, Operable, Understandable, Robust
2. **Semantic Structure**: Use correct HTML elements
3. **Keyboard Support**: All functionality keyboard-accessible
4. **Assistive Technology**: Works with screen readers

### Accessibility Principles
- **Equal access**: Everyone can use the interface
- **Independence**: No special assistance needed
- **Progressive enhancement**: Works without JavaScript
- **Graceful degradation**: Fallbacks for limitations

---

## 5. Technical Foundation

### WCAG 2.2 Success Criteria Overview

**Level A (Minimum)**:
- Non-text content has alternatives
- Keyboard accessible
- No keyboard traps
- Timing adjustable

**Level AA (Standard)**:
- Color contrast 4.5:1 (text), 3:1 (large text)
- Resize text to 200%
- Images of text avoided
- Multiple ways to find pages
- Focus visible

**Level AAA (Enhanced)**:
- Color contrast 7:1
- Sign language for media
- Extended audio description

---

## 6. Implementation Patterns

### 6.1 Semantic HTML

```html
<!-- Correct landmark usage -->
<header role="banner">
  <nav aria-label="Main navigation">
    <ul>
      <li><a href="/">Home</a></li>
      <li><a href="/about">About</a></li>
    </ul>
  </nav>
</header>

<main role="main">
  <article>
    <h1>Page Title</h1>
    <section aria-labelledby="section-heading">
      <h2 id="section-heading">Section Title</h2>
      <p>Content...</p>
    </section>
  </article>
</main>

<footer role="contentinfo">
  <!-- Footer content -->
</footer>
```

### 6.2 Form Accessibility

```html
<form>
  <div>
    <label for="email">Email address</label>
    <input
      type="email"
      id="email"
      name="email"
      autocomplete="email"
      aria-required="true"
      aria-describedby="email-hint email-error"
    />
    <p id="email-hint" class="hint">We'll never share your email</p>
    <p id="email-error" class="error" aria-live="polite"></p>
  </div>
  <button type="submit">Save preferences</button>
</form>
```

### 6.3 Live Regions

```html
<!-- Status updates -->
<div role="status" aria-live="polite" aria-atomic="true">
  <!-- Status messages appear here -->
</div>

<!-- Alert messages -->
<div role="alert" aria-live="assertive">
  <!-- Critical alerts appear here -->
</div>
```

### 6.4 Focus Styles

```css
:focus-visible {
  outline: 2px solid var(--color-primary-500);
  outline-offset: 2px;
}

:focus:not(:focus-visible) {
  outline: none;
}
```

---

## 7. Common Mistakes

### DON'T: Use Color Alone

```html
<!-- Bad -->
<span style="color: red;">Error</span>

<!-- Good -->
<span class="error">
  <svg aria-hidden="true"><!-- error icon --></svg>
  Error: Invalid email format
</span>
```

### DON'T: Use Non-Semantic Elements

```html
<!-- Bad -->
<div onclick="handleClick()">Click me</div>

<!-- Good -->
<button type="button" onclick="handleClick()">Click me</button>
```

### DON'T: Hide Focus Indicators

```css
/* Bad */
*:focus { outline: none; }

/* Good */
*:focus-visible { outline: 2px solid var(--color-primary); }
```

---

## 8. Pre-Implementation Checklist

### Phase 1: Before Writing Code
- [ ] Write accessibility tests with jest-axe/vitest
- [ ] Define keyboard navigation flow
- [ ] Plan focus management strategy
- [ ] Identify ARIA requirements
- [ ] Check color contrast ratios

### Phase 2: During Implementation
- [ ] Use semantic HTML elements
- [ ] Add proper ARIA only when needed
- [ ] Implement keyboard handlers
- [ ] Add visible focus styles
- [ ] Support prefers-reduced-motion
- [ ] Test with screen reader during development

### Phase 3: Before Committing
- [ ] All accessibility tests pass
- [ ] Lighthouse accessibility score >= 90
- [ ] axe-core passes with no errors
- [ ] Keyboard-only navigation works
- [ ] Screen reader announces correctly
- [ ] Color contrast verified
- [ ] Touch targets >= 44px

---

## 9. Summary

Your goal is to create interfaces that are:
- **Perceivable**: Users can sense the content
- **Operable**: Users can navigate and interact
- **Understandable**: Users can comprehend content and operation
- **Robust**: Content works with assistive technologies

Accessibility is not a feature - it's a requirement. Every interface you create should work for everyone, regardless of ability. Test early, test often, and involve users with disabilities in your design process.

Build interfaces that include everyone.
