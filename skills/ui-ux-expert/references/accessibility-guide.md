# Accessibility Implementation Guide

> **Reference Document**: Comprehensive WCAG 2.2 implementation guide, screen reader testing procedures, and keyboard navigation patterns for the UI/UX Expert skill.

---

## Table of Contents

1. [WCAG 2.2 Overview](#wcag-22-overview)
2. [Complete WCAG 2.2 Success Criteria](#complete-wcag-22-success-criteria)
3. [Color & Contrast Guidelines](#color--contrast-guidelines)
4. [Keyboard Navigation Patterns](#keyboard-navigation-patterns)
5. [Screen Reader Implementation](#screen-reader-implementation)
6. [ARIA Patterns & Best Practices](#aria-patterns--best-practices)
7. [Form Accessibility](#form-accessibility)
8. [Testing with Assistive Technologies](#testing-with-assistive-technologies)
9. [Common Accessibility Violations](#common-accessibility-violations)
10. [Accessibility Checklist](#accessibility-checklist)

---

## 1. WCAG 2.2 Overview

### The Four Principles (POUR)

**Perceivable**: Information and user interface components must be presentable to users in ways they can perceive.
- If they can't perceive it, they can't use it
- Provide text alternatives, captions, adaptable content, distinguishable elements

**Operable**: User interface components and navigation must be operable.
- Users must be able to operate the interface
- Keyboard accessible, enough time, no seizures, navigable, input modalities

**Understandable**: Information and the operation of user interface must be understandable.
- Users must understand the information and interface operation
- Readable, predictable, input assistance

**Robust**: Content must be robust enough that it can be interpreted reliably by a wide variety of user agents, including assistive technologies.
- Must work with current and future tools
- Compatible with assistive technologies

---

### Conformance Levels

**Level A** (Minimum):
- Essential accessibility features
- Basic support for assistive technologies
- Legal minimum in many jurisdictions

**Level AA** (Recommended):
- Addresses the biggest and most common barriers
- Industry standard for most organizations
- Required by most accessibility laws (ADA, Section 508)

**Level AAA** (Enhanced):
- Highest level of accessibility
- Not required for entire sites
- May not be achievable for all content

**Recommendation**: Aim for Level AA compliance across all content, with AAA where feasible.

---

## 2. Complete WCAG 2.2 Success Criteria

### Principle 1: Perceivable

#### 1.1 Text Alternatives

**1.1.1 Non-text Content (Level A)**:
- All non-text content has a text alternative
- Images: Use alt text describing the image
- Decorative images: Use empty alt (`alt=""`)
- Complex images: Provide long descriptions

```html
<!-- Informative image -->
<img src="chart.png" alt="Sales increased 25% in Q3 2025">

<!-- Decorative image -->
<img src="divider.png" alt="" role="presentation">

<!-- Complex image with long description -->
<img src="complex-diagram.png" alt="System architecture diagram"
     aria-describedby="diagram-desc">
<div id="diagram-desc">
  The diagram shows three tiers: presentation layer with React components,
  business logic layer with Node.js services, and data layer with PostgreSQL.
</div>

<!-- Icons with labels -->
<button>
  <svg aria-hidden="true">...</svg>
  <span>Save</span>
</button>
```

---

#### 1.2 Time-based Media

**1.2.1 Audio-only and Video-only (Level A)**:
- Provide transcripts for audio-only content
- Provide audio descriptions or transcripts for video-only

**1.2.2 Captions (Level A)**:
- Provide captions for all prerecorded video with audio
- Include speech and important sounds

**1.2.3 Audio Description or Media Alternative (Level A)**:
- Provide audio description or full text alternative for video

**1.2.4 Captions (Live) (Level AA)**:
- Provide live captions for live audio content

**1.2.5 Audio Description (Level AA)**:
- Provide audio description for all prerecorded video

```html
<video controls>
  <source src="tutorial.mp4" type="video/mp4">
  <track kind="captions" src="captions-en.vtt" srclang="en" label="English">
  <track kind="descriptions" src="descriptions.vtt" srclang="en">
</video>
```

---

#### 1.3 Adaptable

**1.3.1 Info and Relationships (Level A)**:
- Use semantic HTML to convey structure
- Headings, lists, tables, forms properly marked up

```html
<!-- Use semantic elements -->
<nav>...</nav>
<main>...</main>
<article>...</article>
<aside>...</aside>

<!-- Proper heading hierarchy -->
<h1>Page Title</h1>
  <h2>Section</h2>
    <h3>Subsection</h3>

<!-- Lists for list content -->
<ul>
  <li>Item 1</li>
  <li>Item 2</li>
</ul>
```

**1.3.2 Meaningful Sequence (Level A)**:
- Reading order matches visual order
- Use CSS for visual positioning, not markup order

**1.3.3 Sensory Characteristics (Level A)**:
- Don't rely solely on shape, size, location, or sound
- "Click the round button" → "Click the Save button (round, blue)"

**1.3.4 Orientation (Level AA)**:
- Don't restrict content to single orientation (portrait/landscape)
- Unless specific orientation is essential

**1.3.5 Identify Input Purpose (Level AA)**:
- Use autocomplete attributes for common fields

```html
<input type="text" name="name" autocomplete="name">
<input type="email" name="email" autocomplete="email">
<input type="tel" name="phone" autocomplete="tel">
```

**1.3.6 Identify Purpose (Level AAA)**:
- Programmatically identify the purpose of icons, regions, and UI components

---

#### 1.4 Distinguishable

**1.4.1 Use of Color (Level A)**:
- Don't use color as the only visual means of conveying information
- Combine color with text, icons, or patterns

```html
<!-- ❌ BAD: Color only -->
<p style="color: red;">Error: Invalid email</p>

<!-- ✅ GOOD: Color + icon + text -->
<p class="error">
  <span aria-hidden="true">⚠️</span>
  <span>Error: Invalid email</span>
</p>
```

**1.4.2 Audio Control (Level A)**:
- If audio plays automatically for > 3 seconds, provide control to pause/stop

**1.4.3 Contrast (Minimum) (Level AA)**:
- Text: 4.5:1 contrast ratio
- Large text (≥24px or ≥19px bold): 3:1 contrast ratio

**1.4.4 Resize Text (Level AA)**:
- Text can be resized up to 200% without loss of content or functionality

**1.4.5 Images of Text (Level AA)**:
- Use real text instead of images of text
- Exception: logos, essential representation

**1.4.6 Contrast (Enhanced) (Level AAA)**:
- Text: 7:1 contrast ratio
- Large text: 4.5:1 contrast ratio

**1.4.10 Reflow (Level AA)**:
- Content reflows to single column at 320px width
- No horizontal scrolling at 400% zoom

**1.4.11 Non-text Contrast (Level AA)**:
- UI components and graphical objects: 3:1 contrast ratio
- Buttons, form borders, focus indicators, charts

**1.4.12 Text Spacing (Level AA)**:
- No loss of content when users adjust:
  - Line height: 1.5x font size
  - Paragraph spacing: 2x font size
  - Letter spacing: 0.12x font size
  - Word spacing: 0.16x font size

**1.4.13 Content on Hover or Focus (Level AA)**:
- Additional content on hover/focus must be:
  - Dismissible (Escape key)
  - Hoverable (pointer can move over new content)
  - Persistent (stays visible until dismissed)

---

### Principle 2: Operable

#### 2.1 Keyboard Accessible

**2.1.1 Keyboard (Level A)**:
- All functionality available via keyboard
- No keyboard traps

```html
<!-- Make custom elements keyboard accessible -->
<div role="button" tabindex="0" onclick="..." onkeydown="handleKey(event)">
  Custom Button
</div>

<script>
function handleKey(event) {
  if (event.key === 'Enter' || event.key === ' ') {
    // Trigger action
  }
}
</script>
```

**2.1.2 No Keyboard Trap (Level A)**:
- Focus can move away from any component using only keyboard
- If it requires more than unmodified arrow/tab keys, advise user

**2.1.3 Keyboard (No Exception) (Level AAA)**:
- All functionality available via keyboard with no exceptions

**2.1.4 Character Key Shortcuts (Level A)**:
- If single character shortcuts exist, must have option to:
  - Turn off
  - Remap
  - Only active when component has focus

---

#### 2.2 Enough Time

**2.2.1 Timing Adjustable (Level A)**:
- For time limits, allow user to:
  - Turn off
  - Adjust (at least 10x default)
  - Extend (warn before expiring)

**2.2.2 Pause, Stop, Hide (Level A)**:
- Moving, blinking, scrolling content can be paused
- Auto-updating info can be paused/hidden/controlled

```html
<!-- Carousel with pause button -->
<div class="carousel">
  <button aria-label="Pause carousel">⏸</button>
  <!-- Carousel content -->
</div>
```

**2.2.3 No Timing (Level AAA)**:
- No time limits (exceptions: real-time events, essential timing)

**2.2.4 Interruptions (Level AAA)**:
- Interruptions can be postponed or suppressed

**2.2.5 Re-authenticating (Level AAA)**:
- When session expires, user can re-authenticate without data loss

**2.2.6 Timeouts (Level AAA)**:
- Users are warned of session timeouts

---

#### 2.3 Seizures and Physical Reactions

**2.3.1 Three Flashes or Below Threshold (Level A)**:
- No content flashes more than 3 times per second
- Or flashes are below general flash and red flash thresholds

**2.3.2 Three Flashes (Level AAA)**:
- No content flashes more than 3 times per second (no exceptions)

**2.3.3 Animation from Interactions (Level AAA)**:
- Motion animation from interactions can be disabled
- Unless essential to functionality

```css
/* Respect user's motion preferences */
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}
```

---

#### 2.4 Navigable

**2.4.1 Bypass Blocks (Level A)**:
- Mechanism to bypass repeated blocks (skip links)

```html
<a href="#main-content" class="skip-link">Skip to main content</a>
<nav>...</nav>
<main id="main-content">...</main>
```

**2.4.2 Page Titled (Level A)**:
- Pages have descriptive titles

```html
<title>Shopping Cart - Your Store</title>
```

**2.4.3 Focus Order (Level A)**:
- Focusable components receive focus in order that preserves meaning

**2.4.4 Link Purpose (In Context) (Level A)**:
- Purpose of each link can be determined from link text or context

```html
<!-- ❌ BAD -->
<a href="/article">Read more</a>

<!-- ✅ GOOD -->
<a href="/article">Read more about accessibility guidelines</a>

<!-- ✅ ALSO GOOD -->
<h2>Accessibility Guidelines</h2>
<p>Learn about WCAG 2.2...</p>
<a href="/article">Read more</a>
```

**2.4.5 Multiple Ways (Level AA)**:
- More than one way to locate pages (sitemap, search, navigation)

**2.4.6 Headings and Labels (Level AA)**:
- Headings and labels are descriptive

**2.4.7 Focus Visible (Level AA)**:
- Keyboard focus indicator is visible

```css
/* Clear focus indicator */
button:focus {
  outline: 3px solid #0066CC;
  outline-offset: 2px;
}
```

**2.4.8 Location (Level AAA)**:
- Information about user's location is available (breadcrumbs)

**2.4.9 Link Purpose (Link Only) (Level AAA)**:
- Purpose of each link determined from link text alone

**2.4.10 Section Headings (Level AAA)**:
- Section headings organize content

**2.4.11 Focus Not Obscured (Minimum) (Level AA)** ⭐ NEW IN 2.2:
- When component receives focus, it's not entirely hidden by author-created content
- At least part of focus indicator is visible

**2.4.12 Focus Not Obscured (Enhanced) (Level AAA)** ⭐ NEW IN 2.2:
- When component receives focus, no part is hidden by author-created content

**2.4.13 Focus Appearance (Level AAA)** ⭐ NEW IN 2.2:
- Focus indicator has minimum size and contrast
- Area >= 2 CSS pixels solid border OR equivalent area
- Contrast >= 3:1 against unfocused state and background

```css
/* WCAG 2.2 compliant focus indicator */
button:focus {
  outline: 2px solid #0066CC; /* 2px minimum */
  outline-offset: 2px;
  /* Ensures 3:1 contrast against background */
}
```

---

#### 2.5 Input Modalities

**2.5.1 Pointer Gestures (Level A)**:
- All path-based or multipoint gestures have single-pointer alternative
- Pinch-to-zoom → +/- buttons

**2.5.2 Pointer Cancellation (Level A)**:
- For single-pointer activation:
  - No down-event triggers action
  - Or action on up-event with abort mechanism
  - Or reversible action

**2.5.3 Label in Name (Level A)**:
- Accessible name contains visible label text
- If button shows "Search", accessible name should include "Search"

```html
<!-- ✅ GOOD: Visual and accessible name match -->
<button aria-label="Search products">Search</button>

<!-- ❌ BAD: Visual and accessible name don't match -->
<button aria-label="Find items">Search</button>
```

**2.5.4 Motion Actuation (Level A)**:
- Functionality triggered by device motion can also be operated by UI
- Provide disable option for motion activation

**2.5.5 Target Size (Enhanced) (Level AAA)**:
- Interactive targets are at least 44x44 CSS pixels
- Exceptions: inline, essential, user-controlled

**2.5.6 Concurrent Input Mechanisms (Level AAA)**:
- Don't restrict use of input modalities
- Support touch, keyboard, mouse simultaneously

**2.5.7 Dragging Movements (Level AA)** ⭐ NEW IN 2.2:
- All functionality that uses dragging has single-pointer alternative
- Drag-to-reorder → Up/Down buttons

```html
<!-- Provide keyboard alternative to drag-and-drop -->
<ul>
  <li>
    Item 1
    <button aria-label="Move up">↑</button>
    <button aria-label="Move down">↓</button>
  </li>
</ul>
```

**2.5.8 Target Size (Minimum) (Level AA)** ⭐ NEW IN 2.2:
- Interactive targets at least 24x24 CSS pixels
- Exceptions:
  - Spacing: Sufficient spacing (24px) between targets
  - Inline: Targets in sentence/block of text
  - User agent control: Browser controls
  - Essential: Particular presentation is essential

```css
/* Ensure minimum 24x24 touch targets */
button {
  min-width: 24px;
  min-height: 24px;
  /* Better: 44x44px for comfortable use */
  min-width: 44px;
  min-height: 44px;
}
```

---

### Principle 3: Understandable

#### 3.1 Readable

**3.1.1 Language of Page (Level A)**:
- Default language of page is programmatically determined

```html
<html lang="en">
```

**3.1.2 Language of Parts (Level AA)**:
- Language of passages or phrases can be determined

```html
<p>The French phrase <span lang="fr">bon appétit</span> means enjoy your meal.</p>
```

**3.1.3 Unusual Words (Level AAA)**:
- Mechanism to identify specific definitions of jargon/idioms

**3.1.4 Abbreviations (Level AAA)**:
- Mechanism to identify expanded form of abbreviations

**3.1.5 Reading Level (Level AAA)**:
- Supplemental content for text requiring > lower secondary education reading level

**3.1.6 Pronunciation (Level AAA)**:
- Mechanism to identify pronunciation when meaning is ambiguous

---

#### 3.2 Predictable

**3.2.1 On Focus (Level A)**:
- Receiving focus doesn't initiate change of context
- No auto-submit on focus

**3.2.2 On Input (Level A)**:
- Changing input doesn't automatically change context
- Provide submit button instead of auto-submit on input change

```html
<!-- ❌ BAD: Auto-submits on change -->
<select onchange="this.form.submit()">

<!-- ✅ GOOD: Explicit submit -->
<select>...</select>
<button type="submit">Go</button>
```

**3.2.3 Consistent Navigation (Level AA)**:
- Repeated navigation occurs in same relative order

**3.2.4 Consistent Identification (Level AA)**:
- Components with same functionality are identified consistently
- If a search icon appears multiple times, use same label

**3.2.5 Change on Request (Level AAA)**:
- Changes of context initiated only by user request
- Or mechanism to turn off such changes

**3.2.6 Consistent Help (Level A)** ⭐ NEW IN 2.2:
- Help mechanisms appear in same relative order across pages
- If help link is in header, keep it there on all pages

```html
<!-- Consistent help placement across pages -->
<header>
  <nav>
    <a href="/help">Help</a> <!-- Always in same position -->
  </nav>
</header>
```

---

#### 3.3 Input Assistance

**3.3.1 Error Identification (Level A)**:
- Input errors are identified and described in text

```html
<input aria-invalid="true" aria-describedby="email-error">
<span id="email-error" role="alert">
  Please enter a valid email address
</span>
```

**3.3.2 Labels or Instructions (Level A)**:
- Labels or instructions provided when input is required

**3.3.3 Error Suggestion (Level AA)**:
- Suggestions for fixing input errors (when known)

```html
<span id="password-error" role="alert">
  Password must be at least 8 characters and include a number
</span>
```

**3.3.4 Error Prevention (Legal, Financial, Data) (Level AA)**:
- For legal/financial transactions, provide:
  - Reversible submissions
  - Data validation with correction opportunity
  - Confirmation page with review option

**3.3.5 Help (Level AAA)**:
- Context-sensitive help is available

**3.3.6 Error Prevention (All) (Level AAA)**:
- Error prevention for all user input

**3.3.7 Redundant Entry (Level A)** ⭐ NEW IN 2.2:
- Don't ask for same information twice in same session
- Unless re-entering is essential or ensures security

```html
<!-- ❌ BAD: Asking for email twice -->
<input type="email" name="email" autocomplete="email">
<input type="email" name="confirm-email">

<!-- ✅ GOOD: Auto-fill from earlier entry or allow copy -->
<input type="email" name="billing-email" autocomplete="email">
<!-- If user already entered email, pre-fill or provide copy option -->
<button type="button">Use account email</button>
```

**3.3.8 Accessible Authentication (Minimum) (Level AA)** ⭐ NEW IN 2.2:
- Authentication doesn't rely on cognitive function test
- Provide alternatives to:
  - CAPTCHAs (use object recognition or biometric)
  - Memory tests (allow password paste, password managers)

```html
<!-- ✅ GOOD: Allow paste in password field -->
<input type="password" name="password" autocomplete="current-password">
<!-- Don't use: onpaste="return false" -->

<!-- ✅ GOOD: Alternative to CAPTCHA -->
<!-- Use object recognition, reCAPTCHA v3, or other accessible methods -->
```

**3.3.9 Accessible Authentication (Enhanced) (Level AAA)** ⭐ NEW IN 2.2:
- No cognitive function test for any step in authentication
- Stricter than 3.3.8

---

### Principle 4: Robust

#### 4.1 Compatible

**4.1.1 Parsing (Level A)** - Obsolete in WCAG 2.2:
- Removed in WCAG 2.2 as browsers now handle parsing errors

**4.1.2 Name, Role, Value (Level A)**:
- All UI components have programmatically determined name and role
- States/properties can be programmatically set

```html
<!-- Name: aria-label, Role: button, State: aria-pressed -->
<button aria-label="Like" aria-pressed="false">
  👍
</button>
```

**4.1.3 Status Messages (Level AA)**:
- Status messages can be determined by assistive technologies
- Use ARIA live regions

```html
<div role="status" aria-live="polite">
  3 items added to cart
</div>

<div role="alert" aria-live="assertive">
  Error: Payment failed
</div>
```

---

## 3. Color & Contrast Guidelines

### 3.1 Contrast Ratios

**WCAG 2.2 Level AA Requirements**:

| Element Type | Minimum Ratio | Formula |
|--------------|---------------|---------|
| Normal text (< 24px) | 4.5:1 | (L1 + 0.05) / (L2 + 0.05) |
| Large text (≥ 24px or ≥ 19px bold) | 3:1 | Where L1 = lighter, L2 = darker |
| UI components | 3:1 | Buttons, borders, icons |
| Graphical objects | 3:1 | Charts, infographics |
| Focus indicators | 3:1 | Against unfocused state |

**WCAG 2.2 Level AAA Requirements**:
- Normal text: 7:1
- Large text: 4.5:1

---

### 3.2 Accessible Color Palettes

**High Contrast Combinations** (AA Compliant):

```
Dark on Light:
- #000000 on #FFFFFF (21:1)    ✅ AAA
- #333333 on #FFFFFF (12.6:1)  ✅ AAA
- #666666 on #FFFFFF (5.7:1)   ✅ AA
- #767676 on #FFFFFF (4.6:1)   ✅ AA
- #959595 on #FFFFFF (3.9:1)   ❌ Fails AA

Light on Dark:
- #FFFFFF on #000000 (21:1)    ✅ AAA
- #FFFFFF on #2C3E50 (8.4:1)   ✅ AAA
- #FFFFFF on #0066CC (4.5:1)   ✅ AA
- #FFFFFF on #4A90E2 (3.0:1)   ❌ Fails AA for text

Semantic Colors (on white):
- Success: #2E7D32 (4.5:1) ✅
- Warning: #F57C00 (3.5:1) ⚠️ AA for large text only
- Error: #C62828 (5.5:1) ✅
- Info: #0277BD (4.5:1) ✅
```

---

### 3.3 Testing Color Contrast

**Tools**:
- WebAIM Contrast Checker: https://webaim.org/resources/contrastchecker/
- Stark (Figma plugin)
- Chrome DevTools Accessibility Panel
- Colour Contrast Analyser (CCA)
- axe DevTools browser extension

**Process**:
1. Identify all text and UI elements
2. Measure contrast against background
3. Document failing elements
4. Adjust colors to meet requirements
5. Re-test after changes

---

### 3.4 Color Independence

Don't rely on color alone to convey information:

```html
<!-- ❌ BAD: Color only -->
<p style="color: red;">Required field</p>

<!-- ✅ GOOD: Color + text -->
<p class="required">
  <span aria-label="Required">*</span> Email
</p>

<!-- ❌ BAD: Color-coded status -->
<div style="background: green;">Active</div>
<div style="background: red;">Inactive</div>

<!-- ✅ GOOD: Icon + text + color -->
<div class="status status-active">
  <span aria-hidden="true">✓</span> Active
</div>
<div class="status status-inactive">
  <span aria-hidden="true">✗</span> Inactive
</div>
```

---

## 4. Keyboard Navigation Patterns

### 4.1 Tab Order

**Logical Tab Order**:
- Left to right, top to bottom (in English)
- Follow visual layout
- Skip decorative elements
- Don't use positive tabindex values

```html
<!-- ✅ GOOD: Natural tab order -->
<input type="text">        <!-- tabindex: 0 (natural) -->
<button>Submit</button>    <!-- tabindex: 0 (natural) -->

<!-- ❌ BAD: Positive tabindex -->
<button tabindex="3">Third</button>
<button tabindex="1">First</button>  <!-- Confusing -->
<button tabindex="2">Second</button>
```

**Tab Index Values**:
- `tabindex="0"`: Natural tab order (focusable)
- `tabindex="-1"`: Programmatically focusable (not in tab order)
- `tabindex="1+"`: Custom tab order (avoid!)

---

### 4.2 Focus Management

**Focus Indicators**:
```css
/* Clear, visible focus indicator */
:focus {
  outline: 3px solid #0066CC;
  outline-offset: 2px;
}

/* Never remove focus without replacement */
/* ❌ BAD */
:focus {
  outline: none; /* Removes focus indicator */
}

/* ✅ GOOD: Custom focus style */
:focus {
  outline: none;
  box-shadow: 0 0 0 3px rgba(0, 102, 204, 0.5);
  border-color: #0066CC;
}
```

**Focus Traps**:
```javascript
// Modal: Trap focus within dialog
function trapFocus(modal) {
  const focusableElements = modal.querySelectorAll(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
  );
  const firstElement = focusableElements[0];
  const lastElement = focusableElements[focusableElements.length - 1];

  modal.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
      if (e.shiftKey && document.activeElement === firstElement) {
        e.preventDefault();
        lastElement.focus();
      } else if (!e.shiftKey && document.activeElement === lastElement) {
        e.preventDefault();
        firstElement.focus();
      }
    }
  });
}
```

---

### 4.3 Keyboard Shortcuts

**Standard Keyboard Interactions**:

| Key | Action |
|-----|--------|
| Tab | Move forward through focusable elements |
| Shift + Tab | Move backward |
| Enter | Activate button/link |
| Space | Activate button, toggle checkbox |
| Escape | Close modal/menu, cancel action |
| Arrow keys | Navigate within component (tabs, menus, lists) |
| Home | First item |
| End | Last item |
| Page Up/Down | Scroll or navigate by page |

**Component-Specific Patterns**:

**Dropdown Menu**:
```javascript
// Arrow keys to navigate menu items
menuButton.addEventListener('keydown', (e) => {
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    openMenu();
    focusFirstItem();
  }
});

menuItems.forEach((item, index) => {
  item.addEventListener('keydown', (e) => {
    switch(e.key) {
      case 'ArrowDown':
        e.preventDefault();
        focusNextItem(index);
        break;
      case 'ArrowUp':
        e.preventDefault();
        focusPreviousItem(index);
        break;
      case 'Escape':
        closeMenu();
        menuButton.focus();
        break;
    }
  });
});
```

**Tabs**:
```javascript
// Arrow keys to navigate tabs, Enter/Space to activate
tabList.addEventListener('keydown', (e) => {
  const tabs = Array.from(tabList.querySelectorAll('[role="tab"]'));
  const currentIndex = tabs.indexOf(document.activeElement);

  switch(e.key) {
    case 'ArrowRight':
    case 'ArrowDown':
      e.preventDefault();
      const nextIndex = (currentIndex + 1) % tabs.length;
      tabs[nextIndex].focus();
      break;
    case 'ArrowLeft':
    case 'ArrowUp':
      e.preventDefault();
      const prevIndex = (currentIndex - 1 + tabs.length) % tabs.length;
      tabs[prevIndex].focus();
      break;
    case 'Home':
      e.preventDefault();
      tabs[0].focus();
      break;
    case 'End':
      e.preventDefault();
      tabs[tabs.length - 1].focus();
      break;
  }
});
```

---

### 4.4 Skip Links

**Implementation**:
```html
<style>
.skip-link {
  position: absolute;
  top: -40px;
  left: 0;
  background: #000;
  color: #fff;
  padding: 8px;
  z-index: 100;
}

.skip-link:focus {
  top: 0;
}
</style>

<a href="#main-content" class="skip-link">Skip to main content</a>
<nav>...</nav>
<main id="main-content" tabindex="-1">...</main>
```

---

## 5. Screen Reader Implementation

### 5.1 Semantic HTML

**Use semantic elements first**:
```html
<!-- ✅ GOOD: Semantic HTML -->
<nav>
  <ul>
    <li><a href="/">Home</a></li>
  </ul>
</nav>

<main>
  <article>
    <h1>Article Title</h1>
    <p>Content...</p>
  </article>
</main>

<aside>
  <h2>Related Links</h2>
</aside>

<footer>
  <p>&copy; 2025</p>
</footer>

<!-- ❌ BAD: Generic divs -->
<div class="nav">
  <div class="link">Home</div>
</div>
```

**Semantic Elements Announced by Screen Readers**:
- `<nav>`: "Navigation"
- `<main>`: "Main"
- `<article>`: "Article"
- `<aside>`: "Complementary"
- `<header>`: "Banner" (if top-level)
- `<footer>`: "Content information" (if top-level)
- `<button>`: "Button"
- `<a>`: "Link"

---

### 5.2 Headings Structure

**Proper Heading Hierarchy**:
```html
<h1>Page Title</h1>              <!-- One H1 per page -->
  <h2>Section 1</h2>              <!-- Major sections -->
    <h3>Subsection 1.1</h3>       <!-- Subsections -->
      <h4>Detail 1.1.1</h4>       <!-- Details -->
  <h2>Section 2</h2>
    <h3>Subsection 2.1</h3>

<!-- ❌ BAD: Skipping levels -->
<h1>Title</h1>
<h3>Subsection</h3>  <!-- Skip H2 -->

<!-- ❌ BAD: Using headings for styling -->
<h3 class="small-text">This is just bold text</h3>
<!-- Use CSS instead -->
<p class="emphasized">This is emphasized text</p>
```

**Why It Matters**:
- Screen reader users navigate by headings
- 67% of screen reader users use headings as primary navigation
- Proper hierarchy creates mental model of content

---

### 5.3 ARIA Labels & Descriptions

**aria-label**: Defines accessible name
```html
<button aria-label="Close dialog">×</button>
<a href="/search" aria-label="Search products">🔍</a>
```

**aria-labelledby**: References element(s) that label this element
```html
<div role="dialog" aria-labelledby="dialog-title">
  <h2 id="dialog-title">Confirm Delete</h2>
  ...
</div>
```

**aria-describedby**: References element(s) that describe this element
```html
<input
  type="password"
  aria-describedby="password-requirements"
>
<div id="password-requirements">
  Password must be at least 8 characters
</div>
```

---

### 5.4 ARIA Live Regions

**Announcing Dynamic Changes**:

```html
<!-- Polite: Announced when user is idle -->
<div role="status" aria-live="polite" aria-atomic="true">
  3 items added to cart
</div>

<!-- Assertive: Announced immediately (use sparingly) -->
<div role="alert" aria-live="assertive">
  Error: Payment failed. Please try again.
</div>

<!-- Off: Not announced -->
<div aria-live="off">
  This updates frequently but shouldn't interrupt
</div>
```

**Live Region Properties**:
- `aria-live="off"`: Default, no announcements
- `aria-live="polite"`: Announce when user is idle
- `aria-live="assertive"`: Interrupt immediately
- `aria-atomic="true"`: Announce entire region
- `aria-atomic="false"`: Announce only changed content
- `aria-relevant="additions text"`: What changes to announce

**Common Use Cases**:
```html
<!-- Form validation -->
<span role="alert" aria-live="assertive">
  Email is required
</span>

<!-- Loading indicator -->
<div role="status" aria-live="polite">
  Loading results...
</div>

<!-- Search results count -->
<div role="status" aria-live="polite" aria-atomic="true">
  Found 42 results
</div>
```

---

### 5.5 Hiding Content

**Visually Hidden but Accessible to Screen Readers**:
```css
.visually-hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border-width: 0;
}
```

```html
<button>
  <span class="visually-hidden">Search</span>
  <svg aria-hidden="true">...</svg> <!-- Icon visible only -->
</button>
```

**Hidden from Screen Readers**:
```html
<!-- Decorative images -->
<img src="divider.png" alt="" role="presentation">

<!-- Decorative icons (text label provided separately) -->
<span aria-hidden="true">🔍</span>
<span>Search</span>

<!-- Display: none or hidden attribute hides from everyone -->
<div style="display: none;">Not visible to anyone</div>
<div hidden>Also hidden from everyone</div>
```

---

## 6. ARIA Patterns & Best Practices

### 6.1 First Rule of ARIA

**"No ARIA is better than bad ARIA"**

**Use semantic HTML first**:
```html
<!-- ❌ BAD: Unnecessary ARIA -->
<div role="button" tabindex="0" onclick="...">Click me</div>

<!-- ✅ GOOD: Native button -->
<button onclick="...">Click me</button>

<!-- ❌ BAD: ARIA overriding semantics -->
<button role="link">I'm confused</button>

<!-- ✅ GOOD: Use the right element -->
<a href="/page">Go to page</a>
```

---

### 6.2 Common ARIA Patterns

**Modal Dialog**:
```html
<div
  role="dialog"
  aria-modal="true"
  aria-labelledby="dialog-title"
  aria-describedby="dialog-desc"
>
  <h2 id="dialog-title">Delete Item</h2>
  <p id="dialog-desc">Are you sure you want to delete this item?</p>
  <button>Cancel</button>
  <button>Delete</button>
</div>
```

**Tabs**:
```html
<div class="tabs">
  <div role="tablist" aria-label="Content sections">
    <button role="tab" aria-selected="true" aria-controls="panel1" id="tab1">
      Overview
    </button>
    <button role="tab" aria-selected="false" aria-controls="panel2" id="tab2">
      Details
    </button>
  </div>

  <div role="tabpanel" id="panel1" aria-labelledby="tab1">
    Overview content...
  </div>

  <div role="tabpanel" id="panel2" aria-labelledby="tab2" hidden>
    Details content...
  </div>
</div>
```

**Accordion**:
```html
<div class="accordion">
  <h3>
    <button
      aria-expanded="false"
      aria-controls="section1"
      id="accordion1"
    >
      Section 1
    </button>
  </h3>
  <div id="section1" role="region" aria-labelledby="accordion1" hidden>
    Section 1 content...
  </div>
</div>
```

**Menu/Dropdown**:
```html
<div class="dropdown">
  <button aria-haspopup="true" aria-expanded="false" id="menu-button">
    Actions
  </button>

  <ul role="menu" aria-labelledby="menu-button" hidden>
    <li role="menuitem">
      <button>Edit</button>
    </li>
    <li role="menuitem">
      <button>Delete</button>
    </li>
  </ul>
</div>
```

---

### 6.3 ARIA States & Properties

**Common States** (change frequently):
- `aria-checked`: Checkbox/radio state
- `aria-expanded`: Expanded/collapsed state
- `aria-selected`: Selected state (tabs, options)
- `aria-pressed`: Toggle button state
- `aria-current`: Current item in set
- `aria-disabled`: Disabled but visible
- `aria-hidden`: Hidden from assistive tech
- `aria-invalid`: Validation state

**Common Properties** (rarely change):
- `aria-label`: Accessible name
- `aria-labelledby`: References label element(s)
- `aria-describedby`: References description element(s)
- `aria-haspopup`: Has popup (menu, dialog)
- `aria-controls`: Controls referenced element
- `aria-live`: Live region behavior
- `aria-required`: Required field
- `aria-readonly`: Read-only field

---

## 7. Form Accessibility

### 7.1 Label Association

**Always associate labels with inputs**:
```html
<!-- ✅ GOOD: Explicit association -->
<label for="email">Email Address</label>
<input type="email" id="email" name="email">

<!-- ✅ ALSO GOOD: Implicit association -->
<label>
  Email Address
  <input type="email" name="email">
</label>

<!-- ❌ BAD: No association -->
<div>Email Address</div>
<input type="email" name="email">
```

---

### 7.2 Required Fields

```html
<!-- ✅ GOOD: Multiple indicators -->
<label for="name">
  Full Name <span aria-label="required">*</span>
</label>
<input type="text" id="name" required aria-required="true">

<!-- ✅ ALSO GOOD: Text indicator -->
<label for="email">
  Email Address (required)
</label>
<input type="email" id="email" required>
```

---

### 7.3 Error Handling

```html
<!-- ✅ GOOD: Clear error indication -->
<div class="form-field">
  <label for="email">Email Address *</label>
  <input
    type="email"
    id="email"
    name="email"
    required
    aria-invalid="true"
    aria-describedby="email-error"
  >
  <span id="email-error" class="error" role="alert">
    Please enter a valid email address
  </span>
</div>
```

**Error Summary**:
```html
<!-- Place at top of form after submit -->
<div role="alert" class="error-summary">
  <h2>Please fix the following errors:</h2>
  <ul>
    <li><a href="#email">Email address is required</a></li>
    <li><a href="#password">Password must be at least 8 characters</a></li>
  </ul>
</div>
```

---

### 7.4 Fieldsets & Legends

```html
<!-- ✅ GOOD: Grouped related inputs -->
<fieldset>
  <legend>Shipping Address</legend>
  <label for="street">Street</label>
  <input type="text" id="street" name="street">

  <label for="city">City</label>
  <input type="text" id="city" name="city">
</fieldset>

<fieldset>
  <legend>Contact Method *</legend>
  <label>
    <input type="radio" name="contact" value="email" required>
    Email
  </label>
  <label>
    <input type="radio" name="contact" value="phone" required>
    Phone
  </label>
</fieldset>
```

---

## 8. Testing with Assistive Technologies

### 8.1 Screen Reader Testing

**Popular Screen Readers**:
- **NVDA** (Windows, Free): Most popular free option
- **JAWS** (Windows, Paid): Industry standard
- **VoiceOver** (macOS/iOS, Free): Built-in to Apple devices
- **TalkBack** (Android, Free): Built-in to Android
- **Narrator** (Windows, Free): Built-in to Windows

**Testing Process**:

1. **Navigate with keyboard only** (no mouse)
   - Can you reach all interactive elements?
   - Is focus visible?
   - Is tab order logical?

2. **Enable screen reader**
   - NVDA: Ctrl + Alt + N
   - VoiceOver: Cmd + F5
   - TalkBack: Volume Up + Down (3 seconds)

3. **Navigate by headings** (H key in NVDA/JAWS)
   - Are headings properly nested?
   - Do headings describe content?

4. **Navigate by landmarks** (D key in NVDA/JAWS)
   - Are main regions identified?
   - Can you jump to navigation, main content?

5. **Navigate forms** (F key in NVDA/JAWS)
   - Are labels announced?
   - Are required fields indicated?
   - Are errors announced?

6. **Test dynamic content**
   - Are loading states announced?
   - Are errors announced?
   - Are success messages announced?

---

### 8.2 NVDA Testing Guide

**Basic NVDA Commands**:
- Start NVDA: Ctrl + Alt + N
- Stop NVDA: NVDA + Q
- Stop reading: Ctrl
- Next line: Down Arrow
- Previous line: Up Arrow
- Next heading: H
- Next link: K
- Next form field: F
- Next button: B
- List headings: NVDA + F7, then select Headings
- List links: NVDA + F7, then select Links
- Browse mode: Toggle with NVDA + Space

---

### 8.3 Automated Testing Tools

**Browser Extensions**:
- **axe DevTools**: Comprehensive WCAG testing
- **WAVE**: Visual feedback on accessibility
- **Lighthouse**: Built into Chrome DevTools
- **IBM Equal Access**: WCAG 2.2 compliance

**Command Line Tools**:
- **axe-core**: Automated testing library
- **pa11y**: Automated accessibility testing
- **Lighthouse CI**: Continuous integration

**Testing Workflow**:
1. Run automated tests (catches ~30-40% of issues)
2. Manual keyboard testing
3. Screen reader testing
4. Color contrast validation
5. User testing with people with disabilities

---

## 9. Common Accessibility Violations

### Top 10 Most Common Issues

1. **Low color contrast** (83% of sites)
   - Fix: Use contrast checker, adjust colors

2. **Missing alternative text** (68% of sites)
   - Fix: Add descriptive alt text to images

3. **Empty links** (62% of sites)
   - Fix: Provide accessible name for links

4. **Missing form labels** (53% of sites)
   - Fix: Associate labels with inputs

5. **Missing document language** (31% of sites)
   - Fix: Add `lang` attribute to `<html>`

6. **Empty buttons** (25% of sites)
   - Fix: Provide text or aria-label for buttons

7. **Missing focus indicators** (89% of sites)
   - Fix: Ensure visible focus styles

8. **Keyboard traps** (42% of sites)
   - Fix: Allow keyboard escape from all components

9. **Improper ARIA usage** (36% of sites)
   - Fix: Use semantic HTML first, validate ARIA

10. **Non-semantic HTML** (73% of sites)
    - Fix: Use proper HTML elements

---

## 10. Accessibility Checklist

### Pre-Launch Accessibility Checklist

#### Perceivable
- [ ] All images have alt text
- [ ] Decorative images have empty alt (`alt=""`)
- [ ] Videos have captions
- [ ] Color contrast meets AA standards (4.5:1 for text, 3:1 for UI)
- [ ] Information isn't conveyed by color alone
- [ ] Text can be resized to 200% without loss of content
- [ ] Content reflows at 320px width (no horizontal scrolling)

#### Operable
- [ ] All functionality available via keyboard
- [ ] No keyboard traps
- [ ] Focus indicators are visible (3px minimum)
- [ ] Skip links provided
- [ ] Touch targets are at least 44x44px (24x24px minimum)
- [ ] No content flashes more than 3 times per second
- [ ] Dragging has keyboard alternative
- [ ] Motion can be disabled (prefers-reduced-motion)

#### Understandable
- [ ] Page language is declared (`<html lang="en">`)
- [ ] Form labels are provided
- [ ] Error messages are clear and helpful
- [ ] Required fields are indicated
- [ ] Error suggestions provided
- [ ] Consistent navigation across pages
- [ ] Consistent identification of components
- [ ] Help is consistently placed

#### Robust
- [ ] Valid HTML
- [ ] ARIA used correctly (or not at all)
- [ ] Name, role, value for all UI components
- [ ] Status messages announced to screen readers

#### Testing
- [ ] Automated testing with axe/WAVE/Lighthouse
- [ ] Manual keyboard testing completed
- [ ] Screen reader testing (NVDA/VoiceOver/JAWS)
- [ ] Color contrast validated
- [ ] Zoom to 200% tested
- [ ] Mobile touch targets tested
- [ ] Forms tested for accessibility
- [ ] Dynamic content tested for announcements

#### Documentation
- [ ] Accessibility statement published
- [ ] Known issues documented
- [ ] Contact method for accessibility issues provided
- [ ] VPAT/ACR (if required)

---

## Summary

Accessibility is not optional. It's a legal requirement in many jurisdictions and a moral imperative to ensure digital experiences are available to everyone.

**Key Takeaways**:
1. **WCAG 2.2 Level AA** is the standard to meet
2. **Use semantic HTML** before reaching for ARIA
3. **Test with real assistive technologies**, not just automated tools
4. **Keyboard accessibility** is foundational
5. **Color contrast matters** - always test
6. **Focus indicators must be visible**
7. **Form labels and errors** must be accessible
8. **Dynamic content** must be announced
9. **Test early and often** throughout development
10. **Include users with disabilities** in testing

**Resources**:
- WCAG 2.2: https://www.w3.org/WAI/WCAG22/quickref/
- WebAIM: https://webaim.org/
- A11y Project: https://www.a11yproject.com/
- ARIA Authoring Practices: https://www.w3.org/WAI/ARIA/apg/

Accessibility is a journey, not a destination. Continuously improve and advocate for inclusive design in every project.
