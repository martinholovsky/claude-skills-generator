# UI/UX Design Patterns Library

> **Reference Document**: Comprehensive UI patterns, component design guidelines, and responsive layout examples for the UI/UX Expert skill.

---

## Table of Contents

1. [Navigation Patterns](#navigation-patterns)
2. [Form & Input Patterns](#form--input-patterns)
3. [Data Display Patterns](#data-display-patterns)
4. [Feedback & Communication](#feedback--communication)
5. [Layout Patterns](#layout-patterns)
6. [Mobile-Specific Patterns](#mobile-specific-patterns)
7. [Component Design Guidelines](#component-design-guidelines)
8. [Responsive Design Patterns](#responsive-design-patterns)
9. [Micro-Interactions](#micro-interactions)
10. [Design Tokens & Systems](#design-tokens--systems)

---

## 1. Navigation Patterns

### 1.1 Primary Navigation

**Top Navigation Bar**:
```
Desktop Layout:
┌────────────────────────────────────────────┐
│ [Logo]  Dashboard  Projects  Team  Settings │
│                              [Search] [User] │
└────────────────────────────────────────────┘

Mobile Layout (Hamburger Menu):
┌────────────────────┐
│ [☰]  [Logo]  [🔍] │
└────────────────────┘

When hamburger is tapped:
┌────────────────────┐
│ [×]  Menu          │
├────────────────────┤
│ Dashboard          │
│ Projects           │
│ Team               │
│ Settings           │
│ Help               │
└────────────────────┘
```

**Best Practices**:
- Limit to 5-7 top-level items
- Highlight current page
- Make logo clickable (return to home)
- Responsive: hamburger on mobile
- Sticky on scroll for easy access

**Accessibility**:
- Use `<nav>` element
- Include skip link
- Keyboard navigation support
- ARIA current="page" for active item

---

### 1.2 Sidebar Navigation

**Application Sidebar**:
```
┌─────────────┬──────────────────────────┐
│ Dashboard   │ Content Area             │
│ ─────────   │                          │
│ Projects    │                          │
│ ├─ Active   │                          │
│ ├─ Archived │                          │
│ └─ New      │                          │
│ Team        │                          │
│ Settings    │                          │
│ ├─ Profile  │                          │
│ ├─ Security │                          │
│ └─ Billing  │                          │
│             │                          │
│ [Help]      │                          │
└─────────────┴──────────────────────────┘

Collapsible Sidebar:
[☰] Icon → Sidebar collapses to icon-only view
Saves horizontal space
```

**Best Practices**:
- Keep sidebar width 200-280px
- Use icons + text for clarity
- Allow collapse/expand
- Persist state across sessions
- Group related items
- Place important items at top

**Accessibility**:
- Logical tab order
- Expandable sections use aria-expanded
- Announce collapse/expand state

---

### 1.3 Breadcrumb Navigation

**Pattern**:
```
Home > Products > Electronics > Laptops > MacBook Pro

[Home] > [Products] > [Electronics] > [Laptops] > MacBook Pro
 └─ Clickable links ─┘                           └─ Current page
```

**Implementation**:
```html
<nav aria-label="Breadcrumb">
  <ol class="breadcrumb">
    <li><a href="/">Home</a></li>
    <li><a href="/products">Products</a></li>
    <li><a href="/products/electronics">Electronics</a></li>
    <li aria-current="page">Laptops</li>
  </ol>
</nav>
```

**Best Practices**:
- Show hierarchy, not history
- Last item is current page (not clickable)
- Use chevron (>) or slash (/) separator
- Mobile: Truncate or show last 2-3 levels
- Position at top of content

---

### 1.4 Tab Navigation

**Horizontal Tabs**:
```
┌──────────────────────────────────────┐
│ [Overview]  Details  Reviews  FAQ   │ ← Tabs
├──────────────────────────────────────┤
│                                      │
│  Overview content...                 │
│                                      │
└──────────────────────────────────────┘

Active tab:
- Underline or background color
- Bold text
- Higher visual weight
```

**Implementation**:
```html
<div role="tablist" aria-label="Product information">
  <button role="tab" aria-selected="true" aria-controls="overview-panel">
    Overview
  </button>
  <button role="tab" aria-selected="false" aria-controls="details-panel">
    Details
  </button>
</div>

<div role="tabpanel" id="overview-panel" aria-labelledby="overview-tab">
  Overview content...
</div>
```

**Best Practices**:
- Limit to 3-7 tabs
- Use pills/buttons on mobile
- Swipe gesture support on mobile
- Lazy load content
- Maintain state in URL

**Accessibility**:
- Arrow keys to navigate tabs
- Tab key to move focus to panel
- ARIA roles: tablist, tab, tabpanel

---

### 1.5 Pagination

**Patterns**:
```
Standard Pagination:
[← Previous]  1  [2]  3  4  5  [Next →]
              └─ Current page (highlighted)

Load More:
[Show 10 more items]

Infinite Scroll:
Items...
Items...
[Loading more...]
Items...
```

**Best Practices**:
- Show total pages/items
- Highlight current page
- Disable Previous/Next when appropriate
- Mobile: Larger tap targets
- Consider "Load More" for better control

**Accessibility**:
- Use `<nav>` with aria-label="Pagination"
- Announce current page to screen readers
- Keyboard navigation support

---

## 2. Form & Input Patterns

### 2.1 Text Input Fields

**Standard Input**:
```
Label Above Field:
Email Address *
[________________________]
Helper text: We'll never share your email

With Validation:
Email Address *
[user@example] ⚠️
└─ Please enter a valid email address

Success State:
Email Address *
[user@example.com] ✓

Disabled State:
Email Address
[not-editable-value] (grayed out)
```

**Implementation**:
```html
<!-- Standard Input -->
<div class="form-field">
  <label for="email">Email Address *</label>
  <input
    type="email"
    id="email"
    name="email"
    required
    aria-describedby="email-help"
  >
  <span id="email-help" class="help-text">
    We'll never share your email
  </span>
</div>

<!-- With Error -->
<div class="form-field form-field--error">
  <label for="email">Email Address *</label>
  <input
    type="email"
    id="email"
    name="email"
    aria-invalid="true"
    aria-describedby="email-error"
  >
  <span id="email-error" class="error-message" role="alert">
    Please enter a valid email address
  </span>
</div>
```

**Design Specifications**:
- Input height: 40-48px (desktop), 44-56px (mobile)
- Font size: 16px minimum (prevents zoom on mobile)
- Border: 1px solid, increases to 2px on focus
- Border radius: 4px or 8px (consistent with design system)
- Padding: 12px horizontal
- Label font size: 14px
- Helper text: 12-14px, muted color

---

### 2.2 Form Layout Patterns

**Single Column Layout** (Recommended):
```
┌──────────────────────────┐
│ Full Name *              │
│ [____________________]   │
│                          │
│ Email Address *          │
│ [____________________]   │
│                          │
│ Password *               │
│ [____________________]   │
│                          │
│ [    Submit    ]         │
└──────────────────────────┘

Completion rate: 15-25% higher than multi-column
```

**Multi-Column Layout** (Use sparingly):
```
┌──────────────────────────────────────┐
│ First Name *         Last Name *     │
│ [___________]        [___________]   │
│                                      │
│ Email Address *                      │
│ [____________________________]       │
│                                      │
│ City *               State *         │
│ [___________]        [▼_____]        │
└──────────────────────────────────────┘

Use only for:
- Related fields (first/last name)
- City/State/ZIP
- Start/End dates
```

**Best Practices**:
- Single column for most forms
- Labels above inputs (left-aligned)
- Group related fields with fieldsets
- Show progress for multi-step forms
- Place primary action at bottom
- Align CTAs to the left (follows reading flow)

---

### 2.3 Selection Controls

**Radio Buttons** (Select one):
```
Shipping Method *

⚪ Standard Shipping (5-7 days) - Free
⚫ Express Shipping (2-3 days) - $9.99
⚪ Overnight Shipping (1 day) - $24.99

Design Rules:
- Vertical stack for 2+ options
- Larger tap targets (24px radio + padding)
- Include descriptive text
- Show pricing when relevant
```

**Checkboxes** (Select multiple):
```
Email Preferences

☑ Product updates
☑ Special offers
☐ Newsletter
☐ Partner promotions

Design Rules:
- Vertical stack for clarity
- Allow multi-select
- Consider "Select All" for long lists
```

**Toggle Switch** (On/Off):
```
Notifications

Email notifications    [ON  ●]
Push notifications     [●  OFF]

Use for:
- Binary on/off states
- Immediate effect (no save button)
- Settings pages
```

**Implementation**:
```html
<!-- Radio Group -->
<fieldset>
  <legend>Shipping Method *</legend>
  <label>
    <input type="radio" name="shipping" value="standard" checked>
    Standard Shipping (5-7 days) - Free
  </label>
  <label>
    <input type="radio" name="shipping" value="express">
    Express Shipping (2-3 days) - $9.99
  </label>
</fieldset>

<!-- Checkbox -->
<label>
  <input type="checkbox" name="newsletter" checked>
  Subscribe to newsletter
</label>

<!-- Toggle (Custom) -->
<label class="toggle">
  <input type="checkbox" role="switch" aria-checked="true">
  <span>Email notifications</span>
</label>
```

---

### 2.4 Dropdown & Select Menus

**Standard Select**:
```
Country *
[United States        ▼]

When clicked:
[United States        ▲]
├─ United States
├─ Canada
├─ United Kingdom
├─ Australia
└─ Germany
```

**Searchable Select** (for long lists):
```
Country *
[Type to search...     ▼]

User types "Uni":
[Uni                   ▲]
├─ United States
├─ United Kingdom
└─ United Arab Emirates
```

**Multi-Select**:
```
Skills *
[Select skills...      ▼]

Selected: JavaScript, React, TypeScript
[× JavaScript] [× React] [× TypeScript]
```

**Best Practices**:
- Use native select for < 10 options
- Searchable for 10+ options
- Show selected count for multi-select
- Provide "Clear all" for multi-select
- Mobile: Use native pickers when possible

---

### 2.5 Date & Time Pickers

**Date Picker**:
```
Start Date *
[MM/DD/YYYY]  [📅]

Calendar Popup:
┌─────────────────────┐
│  < August 2025   >  │
├─────────────────────┤
│ Su Mo Tu We Th Fr Sa│
│                 1  2│
│  3  4  5  6  7  8  9│
│ 10 11 12 13 14 15 16│
│ 17 18 [19] 20 21 22 23│  ← Today
│ 24 25 26 27 28 29 30│
│ 31                  │
└─────────────────────┘
```

**Date Range Picker**:
```
[Start Date] to [End Date]

Calendar shows both months side-by-side:
┌─────────────────────────────────────┐
│    August 2025         September 2025│
│  [Calendar 1]          [Calendar 2]  │
│  Start: Aug 15         End: Sep 15   │
└─────────────────────────────────────┘
```

**Best Practices**:
- Allow manual typing + calendar picker
- Validate format as user types
- Show format hint (MM/DD/YYYY)
- Highlight today's date
- Disable past dates for future-only fields
- Mobile: Use native date picker

**Accessibility**:
- Keyboard navigation (arrow keys)
- Tab to navigate calendar
- Enter to select date
- Escape to close

---

### 2.6 File Upload

**Simple Upload**:
```
Profile Picture
┌─────────────────────┐
│  [📁 Upload Icon]   │
│                     │
│  Drag & drop or     │
│  [Browse Files]     │
│                     │
│ Supported: JPG, PNG │
│ Max size: 5MB       │
└─────────────────────┘
```

**Multi-File Upload**:
```
Documents (0/5 uploaded)
┌─────────────────────────────────┐
│ [+] Add Files                   │
├─────────────────────────────────┤
│ ✓ resume.pdf (245 KB) [× Remove]│
│ ⏳ portfolio.pdf (1.2 MB) 67%   │
│   [████████░░] Uploading...     │
└─────────────────────────────────┘
```

**Best Practices**:
- Support drag & drop
- Show file requirements clearly
- Display upload progress
- Allow removing files
- Show file previews for images
- Validate file type and size
- Provide clear error messages

---

## 3. Data Display Patterns

### 3.1 Tables

**Responsive Table**:
```
Desktop:
┌────────────────────────────────────────────────────┐
│ Name            Email              Status   Actions│
├────────────────────────────────────────────────────┤
│ John Doe        john@example.com   Active   [Edit] │
│ Jane Smith      jane@example.com   Pending  [Edit] │
│ Bob Johnson     bob@example.com    Active   [Edit] │
└────────────────────────────────────────────────────┘

Mobile (Stacked Cards):
┌──────────────────────┐
│ John Doe             │
│ john@example.com     │
│ Status: Active       │
│ [Edit]               │
├──────────────────────┤
│ Jane Smith           │
│ jane@example.com     │
│ Status: Pending      │
│ [Edit]               │
└──────────────────────┘
```

**Table Features**:
- Sortable columns (click header)
- Filterable data
- Pagination or infinite scroll
- Row actions (edit, delete)
- Bulk selection
- Responsive layout

**Implementation**:
```html
<table>
  <caption>User Management</caption>
  <thead>
    <tr>
      <th scope="col">
        <button aria-sort="ascending">Name</button>
      </th>
      <th scope="col">Email</th>
      <th scope="col">Status</th>
      <th scope="col">Actions</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>John Doe</td>
      <td>john@example.com</td>
      <td><span class="badge badge-success">Active</span></td>
      <td><button>Edit</button></td>
    </tr>
  </tbody>
</table>
```

---

### 3.2 Cards

**Content Card**:
```
┌──────────────────────────┐
│ [Featured Image]         │
├──────────────────────────┤
│ Card Title               │
│ Short description of     │
│ the card content here.   │
│                          │
│ [Primary Action]         │
└──────────────────────────┘
```

**Card Grid**:
```
┌──────────┐ ┌──────────┐ ┌──────────┐
│ [Image]  │ │ [Image]  │ │ [Image]  │
│ Title    │ │ Title    │ │ Title    │
│ Desc...  │ │ Desc...  │ │ Desc...  │
│ [Action] │ │ [Action] │ │ [Action] │
└──────────┘ └──────────┘ └──────────┘
```

**Best Practices**:
- Consistent card heights in grid
- Clear visual hierarchy
- Limit to 1-2 actions per card
- Use shadow for depth (2-4px)
- Hover state: lift (translateY)
- Mobile: Single column stack

---

### 3.3 Lists

**Simple List**:
```
• Dashboard
• Projects
• Team
• Settings
```

**Interactive List**:
```
┌────────────────────────────────┐
│ ☐ Complete project proposal    │
│   Due: Aug 20, 2025            │
├────────────────────────────────┤
│ ☑ Review pull requests         │
│   Completed: Aug 19, 2025      │
├────────────────────────────────┤
│ ☐ Update documentation         │
│   Due: Aug 25, 2025     [···]  │
└────────────────────────────────┘
```

**Best Practices**:
- Clear visual separation between items
- Include metadata (date, status)
- Provide actions (swipe, menu)
- Support multi-select
- Show count when relevant

---

### 3.4 Empty States

**No Data State**:
```
┌────────────────────────────────┐
│                                │
│        [📂 Empty Icon]         │
│                                │
│    No projects yet             │
│    Create your first project   │
│    to get started              │
│                                │
│    [+ Create Project]          │
│                                │
└────────────────────────────────┘
```

**Search No Results**:
```
┌────────────────────────────────┐
│                                │
│        [🔍 Search Icon]        │
│                                │
│    No results for "javascript" │
│    Try adjusting your filters  │
│    or search term              │
│                                │
│    [Clear Filters]             │
│                                │
└────────────────────────────────┘
```

**Best Practices**:
- Friendly, helpful messaging
- Explain why it's empty
- Provide clear next action
- Use illustrations sparingly
- Don't just say "No data"

---

## 4. Feedback & Communication

### 4.1 Toast Notifications

**Success Toast**:
```
┌──────────────────────────┐
│ ✓ Changes saved          │ ← Auto-dismiss 3-5s
└──────────────────────────┘
```

**Error Toast**:
```
┌──────────────────────────┐
│ ⚠ Failed to save changes │
│ [Retry]         [Dismiss]│ ← Manual dismiss
└──────────────────────────┘
```

**Toast Positioning**:
- Top-right (desktop)
- Bottom (mobile - easier to reach)
- Stack multiple toasts
- Animate in/out smoothly

**Implementation**:
```html
<div role="status" aria-live="polite" class="toast toast-success">
  <span>✓ Changes saved</span>
  <button aria-label="Dismiss">×</button>
</div>
```

---

### 4.2 Alert Banners

**Info Banner**:
```
┌───────────────────────────────────────────┐
│ ℹ️ We've updated our privacy policy.      │
│   [Learn More]                      [×]   │
└───────────────────────────────────────────┘
```

**Warning Banner**:
```
┌───────────────────────────────────────────┐
│ ⚠️ Your trial ends in 3 days.             │
│   [Upgrade Now]                     [×]   │
└───────────────────────────────────────────┘
```

**Critical Alert**:
```
┌───────────────────────────────────────────┐
│ 🚨 Action required: Verify your email     │
│   [Verify Now]                            │
└───────────────────────────────────────────┘
```

**Best Practices**:
- Position at top of page
- Use appropriate severity (info, warning, error)
- Allow dismissal (unless critical)
- Persist critical alerts
- Use color coding + icons

---

### 4.3 Modal Dialogs

**Standard Modal**:
```
[Backdrop - semi-transparent overlay]

┌──────────────────────────────┐
│ Modal Title              [×] │
├──────────────────────────────┤
│                              │
│ Modal content goes here.     │
│ This can include forms,      │
│ confirmations, or info.      │
│                              │
├──────────────────────────────┤
│           [Cancel] [Confirm] │
└──────────────────────────────┘
```

**Best Practices**:
- Trap focus within modal
- Close on Escape key
- Close on backdrop click (optional)
- Disable background scrolling
- Limit width (max 600px)
- Center vertically and horizontally
- Use sparingly - don't interrupt user

**Accessibility**:
```html
<div
  role="dialog"
  aria-modal="true"
  aria-labelledby="modal-title"
  aria-describedby="modal-description"
>
  <h2 id="modal-title">Confirm Delete</h2>
  <p id="modal-description">
    Are you sure you want to delete this item?
  </p>
  <button>Cancel</button>
  <button>Delete</button>
</div>
```

---

### 4.4 Loading States

**Spinner**:
```
[○] Loading...
```

**Skeleton Screen**:
```
┌────────────────────────┐
│ ▓▓▓▓▓▓▓▓░░░░░░░░░░    │ ← Placeholder
│ ░░░░░░░░░░░░░░░░      │
│ ▓▓▓▓░░░░ ▓▓▓▓░░░░    │
└────────────────────────┘
```

**Progress Bar**:
```
Uploading... 67%
[████████████░░░░░░]
```

**Best Practices**:
- Use skeleton screens for < 3s loads
- Show progress for long operations
- Indicate time remaining when possible
- Avoid blocking entire UI
- Provide cancel option for long tasks

---

## 5. Layout Patterns

### 5.1 Dashboard Layout

**3-Column Dashboard**:
```
┌─────────────────────────────────────────────┐
│ [Header with Logo, Search, User]           │
├───────┬─────────────────────┬───────────────┤
│ Nav   │ Main Content        │ Sidebar       │
│       │                     │               │
│ [···] │ [Cards/Widgets]     │ [Activity]    │
│ [···] │                     │ [Quick Links] │
│ [···] │ [Charts/Tables]     │               │
│       │                     │               │
└───────┴─────────────────────┴───────────────┘
```

**Responsive Behavior**:
- Desktop: 3 columns
- Tablet: 2 columns (nav as hamburger)
- Mobile: 1 column (stacked)

---

### 5.2 Landing Page Layout

**Hero Section**:
```
┌───────────────────────────────────────────┐
│ [Navigation Bar]                          │
├───────────────────────────────────────────┤
│                                           │
│          Main Headline                    │
│       Supporting subheadline              │
│                                           │
│      [Primary CTA] [Secondary CTA]        │
│                                           │
│          [Hero Image]                     │
│                                           │
└───────────────────────────────────────────┘
```

**Features Section**:
```
┌──────────┐ ┌──────────┐ ┌──────────┐
│ [Icon]   │ │ [Icon]   │ │ [Icon]   │
│ Feature 1│ │ Feature 2│ │ Feature 3│
│ Desc...  │ │ Desc...  │ │ Desc...  │
└──────────┘ └──────────┘ └──────────┘
```

---

## 6. Mobile-Specific Patterns

### 6.1 Bottom Navigation

**Mobile Tab Bar**:
```
┌────────────────────────┐
│                        │
│   [Content Area]       │
│                        │
├────────────────────────┤
│ [🏠] [📊] [+] [👤] [⚙]│  ← Fixed at bottom
│ Home  Stats Add  User  │
└────────────────────────┘
```

**Best Practices**:
- 3-5 items maximum
- Icons + labels
- Highlight active tab
- Fixed position
- 56-64px height
- Safe area insets (iPhone)

---

### 6.2 Swipe Gestures

**Swipe to Delete**:
```
Normal State:
┌────────────────────────┐
│ Email from John Doe    │
│ Subject: Meeting notes │
└────────────────────────┘

Swipe Left:
┌────────────────────────┐
│ Email from John│[Delete]│
└────────────────────────┘
```

**Pull to Refresh**:
```
Pull down:
↓
[Loading indicator]
↓
Content refreshes
```

---

### 6.3 Touch Zones

**Thumb Zone Map** (Right-handed):
```
┌────────────────────────┐
│ [Hard to reach]        │ ← Top corners
│                        │
│   [Easy to reach]      │ ← Middle
│                        │
│ [Natural thumb zone]   │ ← Bottom third
│    [Primary Actions]   │
└────────────────────────┘
```

**Design Implications**:
- Place primary actions in bottom third
- Navigation at bottom (not top)
- Important content in center
- Avoid top corners for frequent actions

---

## 7. Component Design Guidelines

### 7.1 Buttons

**Button Hierarchy**:
```
[  Primary Button  ]  ← Filled, high contrast
[  Secondary Button  ] ← Outlined
[  Tertiary Button  ]  ← Text only

Size Variants:
[     Large Button     ] (48px height)
[   Medium Button   ]    (40px height)
[  Small Button  ]       (32px height)
```

**Button States**:
```
Default:   [  Button  ]
Hover:     [  Button  ] (darker/lighter)
Active:    [  Button  ] (pressed)
Disabled:  [  Button  ] (grayed, not clickable)
Loading:   [  ⏳ Button  ] (spinner + disabled)
```

**Design Specifications**:
- Border radius: 4-8px
- Padding: 12-24px horizontal, 8-16px vertical
- Font weight: 500-600
- Text transform: none (sentence case preferred)
- Min width: 80px
- Min height: 40px (desktop), 44px (mobile)

---

### 7.2 Input Fields

**Input States**:
```
Default:  [________________________]
Focus:    [________________________] (blue border)
Error:    [________________________] (red border + icon)
Success:  [________________________] (green border + icon)
Disabled: [________________________] (gray, non-editable)
```

**Design Specifications**:
- Height: 40-48px (desktop), 44-56px (mobile)
- Border: 1px solid #CCCCCC
- Focus border: 2px solid primary color
- Border radius: 4px
- Font size: 16px minimum
- Padding: 12px

---

### 7.3 Icons

**Icon Sizes**:
- Small: 16px (inline with text)
- Medium: 24px (default)
- Large: 32px (prominent actions)
- Extra Large: 48px+ (empty states)

**Icon Usage**:
- Use consistent icon library (Material, Feather, etc.)
- Pair with text when possible
- Ensure sufficient contrast
- Make interactive icons 44x44px tap target

---

## 8. Responsive Design Patterns

### 8.1 Breakpoints

**Standard Breakpoints**:
```
Mobile:     < 640px
Tablet:     640px - 1024px
Desktop:    1024px - 1440px
Large:      > 1440px
```

**Media Queries**:
```css
/* Mobile first approach */
.container {
  padding: 16px;
}

@media (min-width: 640px) {
  .container {
    padding: 24px;
  }
}

@media (min-width: 1024px) {
  .container {
    padding: 32px;
  }
}
```

---

### 8.2 Responsive Grid

**12-Column Grid**:
```
Desktop (3 columns):
┌───┬───┬───┬───┐ ┌───┬───┬───┬───┐ ┌───┬───┬───┬───┐
│   Col 1   │ │   Col 2   │ │   Col 3   │
└───────────┘ └───────────┘ └───────────┘

Tablet (2 columns):
┌──────────────────┐ ┌──────────────────┐
│      Col 1       │ │      Col 2       │
└──────────────────┘ └──────────────────┘

Mobile (1 column):
┌────────────────────────────────────┐
│            Col 1                   │
├────────────────────────────────────┤
│            Col 2                   │
├────────────────────────────────────┤
│            Col 3                   │
└────────────────────────────────────┘
```

---

### 8.3 Responsive Typography

**Fluid Typography**:
```css
/* Scales from 16px to 20px based on viewport */
body {
  font-size: clamp(16px, 4vw, 20px);
}

h1 {
  font-size: clamp(28px, 6vw, 48px);
}

/* Responsive line height */
p {
  line-height: 1.6; /* Mobile */
}

@media (min-width: 1024px) {
  p {
    line-height: 1.75; /* Desktop - more spacing */
  }
}
```

---

## 9. Micro-Interactions

### 9.1 Button Hover Effects

```css
.button {
  transition: all 0.2s ease-in-out;
}

.button:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.15);
}

.button:active {
  transform: translateY(0);
}
```

---

### 9.2 Loading Animations

**Pulse Animation**:
```css
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.skeleton {
  animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}
```

---

### 9.3 Transition Timing

**Recommended Durations**:
- Instant: 0ms (state changes)
- Fast: 100-200ms (hover, focus)
- Standard: 200-300ms (most transitions)
- Slow: 300-500ms (complex animations)
- Very slow: 500ms+ (page transitions)

**Easing Functions**:
- ease-in-out: Default for most
- ease-out: Entering elements
- ease-in: Exiting elements
- cubic-bezier: Custom curves

---

## 10. Design Tokens & Systems

### 10.1 Color System

**Primary Colors**:
```
primary-50:  #E3F2FD  (backgrounds)
primary-100: #BBDEFB
primary-200: #90CAF9
primary-300: #64B5F6
primary-400: #42A5F5
primary-500: #2196F3  (main)
primary-600: #1E88E5
primary-700: #1976D2  (hover)
primary-800: #1565C0
primary-900: #0D47A1  (pressed)
```

**Semantic Colors**:
```
success:  #4CAF50
warning:  #FF9800
error:    #F44336
info:     #2196F3
```

**Neutral Colors**:
```
gray-50:  #FAFAFA
gray-100: #F5F5F5
gray-200: #EEEEEE
gray-300: #E0E0E0
gray-400: #BDBDBD
gray-500: #9E9E9E
gray-600: #757575
gray-700: #616161
gray-800: #424242
gray-900: #212121
```

---

### 10.2 Spacing System

**8px Grid**:
```
space-1:  4px
space-2:  8px
space-3:  12px
space-4:  16px
space-5:  24px
space-6:  32px
space-7:  48px
space-8:  64px
space-9:  96px
space-10: 128px
```

**Usage**:
- Component padding: 16px (space-4)
- Section spacing: 48px (space-7)
- Page margins: 24px (space-5)

---

### 10.3 Typography Scale

**Font Sizes**:
```
text-xs:   12px (0.75rem)   - Helper text
text-sm:   14px (0.875rem)  - Secondary
text-base: 16px (1rem)      - Body
text-lg:   18px (1.125rem)  - Intro
text-xl:   20px (1.25rem)   - H4
text-2xl:  24px (1.5rem)    - H3
text-3xl:  30px (1.875rem)  - H2
text-4xl:  36px (2.25rem)   - H1
text-5xl:  48px (3rem)      - Display
```

**Font Weights**:
```
light:    300
regular:  400
medium:   500
semibold: 600
bold:     700
```

**Line Heights**:
```
tight:   1.25 (headings)
normal:  1.5  (body)
relaxed: 1.75 (long-form content)
```

---

### 10.4 Shadows

**Elevation Levels**:
```css
shadow-sm:  0 1px 2px rgba(0,0,0,0.05);
shadow-md:  0 4px 6px rgba(0,0,0,0.1);
shadow-lg:  0 10px 15px rgba(0,0,0,0.15);
shadow-xl:  0 20px 25px rgba(0,0,0,0.2);
shadow-2xl: 0 25px 50px rgba(0,0,0,0.25);
```

**Usage**:
- Cards: shadow-md
- Modals: shadow-xl
- Dropdowns: shadow-lg
- Buttons (hover): shadow-md

---

### 10.5 Border Radius

**Consistent Rounding**:
```
rounded-none: 0px
rounded-sm:   2px
rounded:      4px
rounded-md:   6px
rounded-lg:   8px
rounded-xl:   12px
rounded-2xl:  16px
rounded-full: 9999px (pills, circles)
```

**Usage**:
- Buttons: rounded-lg (8px)
- Inputs: rounded (4px)
- Cards: rounded-lg (8px)
- Avatars: rounded-full
- Tags: rounded-full or rounded-md

---

## Summary

This reference guide provides comprehensive UI/UX patterns for building consistent, accessible, and user-friendly interfaces. Use these patterns as a foundation, but always validate with user testing and adapt to your specific context.

**Key Principles**:
- Consistency across all patterns
- Accessibility baked into every component
- Mobile-first responsive approach
- Clear visual hierarchy
- User feedback for all interactions
- Design system-driven implementation

For accessibility implementation details, see `accessibility-guide.md`.
