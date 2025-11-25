# TypeScript Advanced Patterns

## Complex Generic Patterns

### Mapped Type Transformations

```typescript
// Transform object values with type preservation
type MapValues<T, V> = {
  [K in keyof T]: V
}

// Get paths through object
type Paths<T, P extends string = ''> = T extends object
  ? {
      [K in keyof T & string]: Paths<T[K], `${P}${P extends '' ? '' : '.'}${K}`>
    }[keyof T & string]
  : P
```

### Conditional Type Inference

```typescript
// Extract promise value type
type Awaited<T> = T extends Promise<infer U> ? Awaited<U> : T

// Extract array element type
type ArrayElement<T> = T extends (infer U)[] ? U : never

// Function overload inference
type OverloadReturnType<T> = T extends {
  (...args: any[]): infer R1
  (...args: any[]): infer R2
}
  ? R1 | R2
  : T extends (...args: any[]) => infer R
  ? R
  : never
```

## Builder Pattern with Types

```typescript
class QueryBuilder<T extends object> {
  private query: Partial<T> = {}

  where<K extends keyof T>(key: K, value: T[K]): this {
    this.query[key] = value
    return this
  }

  build(): Partial<T> {
    return { ...this.query }
  }
}

// Type-safe usage
const query = new QueryBuilder<{ status: string; priority: number }>()
  .where('status', 'active')  // ✅ Type checked
  .where('priority', 5)       // ✅ Type checked
  .build()
```

## Event System with Types

```typescript
type EventMap = {
  'command:execute': { commandId: string; action: string }
  'status:change': { from: string; to: string }
  'error:occurred': { code: number; message: string }
}

class TypedEventEmitter<T extends Record<string, any>> {
  private handlers = new Map<keyof T, Set<(data: any) => void>>()

  on<K extends keyof T>(event: K, handler: (data: T[K]) => void): void {
    if (!this.handlers.has(event)) {
      this.handlers.set(event, new Set())
    }
    this.handlers.get(event)!.add(handler)
  }

  emit<K extends keyof T>(event: K, data: T[K]): void {
    this.handlers.get(event)?.forEach(handler => handler(data))
  }
}

// Usage
const events = new TypedEventEmitter<EventMap>()
events.on('command:execute', (data) => {
  console.log(data.commandId)  // ✅ Type-safe
})
```
