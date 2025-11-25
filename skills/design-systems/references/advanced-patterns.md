# Design Systems Advanced Patterns

## Token Transforms with Style Dictionary

```javascript
// style-dictionary.config.js
module.exports = {
  source: ["tokens/**/*.json"],
  platforms: {
    css: {
      transformGroup: "css",
      buildPath: "dist/css/",
      files: [{
        destination: "tokens.css",
        format: "css/variables"
      }]
    },
    js: {
      transformGroup: "js",
      buildPath: "dist/js/",
      files: [{
        destination: "tokens.js",
        format: "javascript/es6"
      }]
    },
    ios: {
      transformGroup: "ios",
      buildPath: "dist/ios/",
      files: [{
        destination: "Tokens.swift",
        format: "ios-swift/class.swift"
      }]
    }
  }
};
```

## Figma Token Integration

```typescript
// Sync tokens from Figma
import { FigmaTokensTransformer } from "@tokens-studio/sd-transforms";

// tokens/figma-export.json
{
  "colors": {
    "primary": {
      "value": "{colors.blue.600}",
      "type": "color"
    }
  },
  "spacing": {
    "sm": {
      "value": "8",
      "type": "spacing"
    }
  }
}

// Transform to Style Dictionary format
const transformed = FigmaTokensTransformer.transform(figmaTokens);
```

## Component Variants with CSS

```css
/* Data attribute based variants */
.button {
  /* Base styles */
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius-md);
  font-weight: var(--font-weight-medium);
  transition: all 150ms ease;
}

/* Size variants */
.button[data-size="sm"] {
  height: 32px;
  padding: 0 var(--space-3);
  font-size: var(--font-size-sm);
}

.button[data-size="md"] {
  height: 40px;
  padding: 0 var(--space-4);
  font-size: var(--font-size-base);
}

.button[data-size="lg"] {
  height: 48px;
  padding: 0 var(--space-5);
  font-size: var(--font-size-lg);
}

/* Variant styles */
.button[data-variant="primary"] {
  background: var(--color-interactive-primary);
  color: var(--color-text-inverse);
}

.button[data-variant="secondary"] {
  background: var(--color-interactive-secondary);
  color: var(--color-text-primary);
  border: 1px solid var(--color-border-default);
}

.button[data-variant="ghost"] {
  background: transparent;
  color: var(--color-interactive-primary);
}
```

## Design Token Documentation

```typescript
// Generate token documentation
interface TokenDoc {
  name: string;
  value: string;
  description: string;
  category: string;
  example?: string;
}

function generateTokenDocs(tokens: Tokens): TokenDoc[] {
  const docs: TokenDoc[] = [];

  for (const [category, values] of Object.entries(tokens)) {
    for (const [key, value] of Object.entries(values)) {
      docs.push({
        name: `--${category}-${key}`,
        value: value.value,
        description: value.description || "",
        category,
        example: generateExample(category, key, value)
      });
    }
  }

  return docs;
}
```

## Component Composition System

```typescript
// Slot-based composition
interface SlottedComponent {
  Root: React.FC;
  Trigger: React.FC;
  Content: React.FC;
  Close: React.FC;
}

const Dialog: SlottedComponent = {
  Root: ({ children }) => (
    <DialogContext.Provider value={useDialogState()}>
      {children}
    </DialogContext.Provider>
  ),

  Trigger: ({ children }) => {
    const { open } = useDialogContext();
    return <button onClick={open}>{children}</button>;
  },

  Content: ({ children }) => {
    const { isOpen } = useDialogContext();
    if (!isOpen) return null;
    return <div role="dialog">{children}</div>;
  },

  Close: ({ children }) => {
    const { close } = useDialogContext();
    return <button onClick={close}>{children}</button>;
  }
};

// Usage
<Dialog.Root>
  <Dialog.Trigger>Open</Dialog.Trigger>
  <Dialog.Content>
    <h2>Title</h2>
    <p>Content</p>
    <Dialog.Close>Close</Dialog.Close>
  </Dialog.Content>
</Dialog.Root>
```

## Version Management

```typescript
// Semantic versioning for design system
interface ChangelogEntry {
  version: string;
  date: string;
  changes: {
    type: "breaking" | "feature" | "fix" | "deprecation";
    component?: string;
    description: string;
  }[];
}

// Migration helper
function createMigration(from: string, to: string) {
  return {
    from,
    to,
    transforms: [
      {
        pattern: /--color-primary/g,
        replacement: "--color-interactive-primary"
      },
      {
        pattern: /Button size="small"/g,
        replacement: 'Button size="sm"'
      }
    ]
  };
}
```

## Multi-Brand Theming

```css
/* Brand-specific token overrides */
:root {
  /* Default brand */
  --brand-color-primary: var(--color-blue-600);
  --brand-color-secondary: var(--color-gray-600);
  --brand-font-family: "Inter", sans-serif;
}

[data-brand="brand-a"] {
  --brand-color-primary: #ff6b00;
  --brand-color-secondary: #333333;
  --brand-font-family: "Roboto", sans-serif;
}

[data-brand="brand-b"] {
  --brand-color-primary: #00a86b;
  --brand-color-secondary: #1a1a1a;
  --brand-font-family: "Open Sans", sans-serif;
}

/* Components use brand tokens */
.button-primary {
  background: var(--brand-color-primary);
  font-family: var(--brand-font-family);
}
```

## Design Token Testing

```typescript
// Test token consistency
describe("Design Tokens", () => {
  it("should have all semantic tokens reference core tokens", () => {
    const semantic = getSemanticTokens();
    const core = getCoreTokens();

    for (const token of Object.values(semantic)) {
      if (token.value.startsWith("var(--")) {
        const referenced = token.value.match(/var\(--([^)]+)\)/)[1];
        expect(core).toHaveProperty(referenced);
      }
    }
  });

  it("should have dark theme equivalents", () => {
    const lightTokens = getThemeTokens("light");
    const darkTokens = getThemeTokens("dark");

    for (const key of Object.keys(lightTokens)) {
      expect(darkTokens).toHaveProperty(key);
    }
  });

  it("should meet contrast requirements", () => {
    const textOnBg = getContrastRatio(
      tokens["color-text-primary"],
      tokens["color-bg-primary"]
    );
    expect(textOnBg).toBeGreaterThanOrEqual(4.5);
  });
});
```
