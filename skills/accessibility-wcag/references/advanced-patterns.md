# Accessibility Advanced Patterns

## Custom Components

### Accessible Dropdown Menu

```typescript
function DropdownMenu({ trigger, items }: Props) {
  const [isOpen, setIsOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const menuRef = useRef<HTMLUListElement>(null);

  const handleKeyDown = (e: KeyboardEvent) => {
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        setActiveIndex(prev =>
          prev < items.length - 1 ? prev + 1 : 0
        );
        break;
      case "ArrowUp":
        e.preventDefault();
        setActiveIndex(prev =>
          prev > 0 ? prev - 1 : items.length - 1
        );
        break;
      case "Enter":
      case " ":
        e.preventDefault();
        if (activeIndex >= 0) {
          items[activeIndex].action();
          setIsOpen(false);
        }
        break;
      case "Escape":
        setIsOpen(false);
        break;
    }
  };

  return (
    <div onKeyDown={handleKeyDown}>
      <button
        aria-haspopup="true"
        aria-expanded={isOpen}
        onClick={() => setIsOpen(!isOpen)}
      >
        {trigger}
      </button>
      {isOpen && (
        <ul
          ref={menuRef}
          role="menu"
          aria-label="Actions"
        >
          {items.map((item, index) => (
            <li
              key={item.id}
              role="menuitem"
              tabIndex={activeIndex === index ? 0 : -1}
              aria-selected={activeIndex === index}
            >
              {item.label}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
```

### Accessible Autocomplete

```typescript
function Autocomplete({ options, onSelect }: Props) {
  const [query, setQuery] = useState("");
  const [isOpen, setIsOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);

  const filtered = options.filter(opt =>
    opt.label.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div role="combobox" aria-expanded={isOpen} aria-haspopup="listbox">
      <label htmlFor="autocomplete-input" id="autocomplete-label">
        Search
      </label>
      <input
        id="autocomplete-input"
        type="text"
        aria-autocomplete="list"
        aria-controls="autocomplete-listbox"
        aria-activedescendant={
          activeIndex >= 0 ? `option-${activeIndex}` : undefined
        }
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onFocus={() => setIsOpen(true)}
      />
      {isOpen && filtered.length > 0 && (
        <ul
          id="autocomplete-listbox"
          role="listbox"
          aria-labelledby="autocomplete-label"
        >
          {filtered.map((option, index) => (
            <li
              key={option.id}
              id={`option-${index}`}
              role="option"
              aria-selected={activeIndex === index}
              onClick={() => onSelect(option)}
            >
              {option.label}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
```

### Accessible Carousel

```typescript
function Carousel({ slides }: Props) {
  const [current, setCurrent] = useState(0);

  return (
    <div
      role="group"
      aria-roledescription="carousel"
      aria-label="Featured content"
    >
      <div role="group" aria-roledescription="slide" aria-label={`${current + 1} of ${slides.length}`}>
        {slides[current].content}
      </div>

      <div role="group" aria-label="Slide controls">
        <button
          aria-label="Previous slide"
          onClick={() => setCurrent(prev => prev > 0 ? prev - 1 : slides.length - 1)}
        >
          Previous
        </button>
        <button
          aria-label="Next slide"
          onClick={() => setCurrent(prev => prev < slides.length - 1 ? prev + 1 : 0)}
        >
          Next
        </button>
      </div>

      <div role="tablist" aria-label="Select slide">
        {slides.map((_, index) => (
          <button
            key={index}
            role="tab"
            aria-selected={current === index}
            aria-label={`Go to slide ${index + 1}`}
            onClick={() => setCurrent(index)}
          />
        ))}
      </div>
    </div>
  );
}
```

## Screen Reader Testing Scripts

```bash
# VoiceOver (macOS)
# Open with: Cmd + F5
# Navigate: Ctrl + Option + Arrow keys
# Interact: Ctrl + Option + Space

# NVDA (Windows)
# Download from nvaccess.org
# Navigate: Arrow keys
# Forms mode: Enter
# Browse mode: Escape

# Testing checklist:
# 1. Can navigate all interactive elements?
# 2. Are all images described?
# 3. Are form labels announced?
# 4. Are errors communicated?
# 5. Is dynamic content announced?
```

## Automated Testing Setup

```typescript
// Jest + axe-core
import { axe, toHaveNoViolations } from "jest-axe";

expect.extend(toHaveNoViolations);

describe("Accessibility", () => {
  it("should have no accessibility violations", async () => {
    const { container } = render(<MyComponent />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});

// Cypress + axe-core
describe("Page Accessibility", () => {
  it("passes axe audit", () => {
    cy.visit("/");
    cy.injectAxe();
    cy.checkA11y();
  });
});
```

## High Contrast Support

```css
/* Support Windows High Contrast Mode */
@media (forced-colors: active) {
  .button {
    border: 2px solid ButtonText;
    background: ButtonFace;
    color: ButtonText;
  }

  .icon {
    forced-color-adjust: none;
  }
}
```

## Print Accessibility

```css
@media print {
  /* Show link URLs */
  a[href]::after {
    content: " (" attr(href) ")";
    font-size: 0.8em;
  }

  /* Ensure readability */
  body {
    color: #000;
    background: #fff;
    font-size: 12pt;
  }

  /* Hide non-essential elements */
  nav, .no-print {
    display: none;
  }
}
```
