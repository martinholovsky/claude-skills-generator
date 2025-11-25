# TypeScript Security Examples

## Runtime Validation Patterns

### Complete API Validation

```typescript
import { z } from 'zod'

// Request validation
const apiRequestSchema = z.object({
  endpoint: z.string().url(),
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE']),
  headers: z.record(z.string()).optional(),
  body: z.unknown().optional()
})

// Response validation
const apiResponseSchema = z.object({
  status: z.number(),
  data: z.unknown(),
  timestamp: z.number()
})

async function safeApiCall(request: z.infer<typeof apiRequestSchema>) {
  const validated = apiRequestSchema.parse(request)
  const response = await fetch(validated.endpoint, {
    method: validated.method,
    headers: validated.headers
  })
  return apiResponseSchema.parse(await response.json())
}
```

### Type-Safe Configuration

```typescript
const configSchema = z.object({
  apiUrl: z.string().url(),
  timeout: z.number().int().positive().max(30000),
  retries: z.number().int().min(0).max(5),
  debug: z.boolean().default(false)
})

type Config = z.infer<typeof configSchema>

function loadConfig(env: Record<string, string | undefined>): Config {
  return configSchema.parse({
    apiUrl: env.API_URL,
    timeout: parseInt(env.TIMEOUT ?? '5000'),
    retries: parseInt(env.RETRIES ?? '3'),
    debug: env.DEBUG === 'true'
  })
}
```

## Preventing Type Confusion

### Branded Primitives for Security

```typescript
// Prevent SQL injection through type safety
declare const __sql: unique symbol
type SafeSQL = string & { [__sql]: true }

function sql(strings: TemplateStringsArray, ...values: unknown[]): SafeSQL {
  // Escape all interpolated values
  const escaped = values.map(v =>
    typeof v === 'string' ? v.replace(/'/g, "''") : String(v)
  )
  return strings.reduce((acc, str, i) =>
    acc + str + (escaped[i] ?? ''), ''
  ) as SafeSQL
}

function executeQuery(query: SafeSQL): Promise<unknown[]> {
  // Only accepts SafeSQL, not arbitrary strings
  return db.query(query)
}

// Usage
const userId = 'user123'
const query = sql`SELECT * FROM users WHERE id = '${userId}'`
await executeQuery(query)  // ✅ Type-safe

// This won't compile:
// await executeQuery(`SELECT * FROM users WHERE id = '${userId}'`)
```

### Sensitive Data Markers

```typescript
// Mark sensitive types to prevent logging
declare const __sensitive: unique symbol

type Sensitive<T> = T & { [__sensitive]: true }

type Password = Sensitive<string>
type APIKey = Sensitive<string>

function createPassword(value: string): Password {
  return value as Password
}

function log(message: string, data?: Record<string, unknown>): void {
  // TypeScript prevents logging sensitive types
  console.log(message, data)
}

// Compile error if trying to log sensitive data directly
const password = createPassword('secret')
// log('Login', { password })  // ❌ Type error
```

## Error Handling Types

### Typed Error Results

```typescript
type Result<T, E = Error> =
  | { success: true; data: T }
  | { success: false; error: E }

function divide(a: number, b: number): Result<number, string> {
  if (b === 0) {
    return { success: false, error: 'Division by zero' }
  }
  return { success: true, data: a / b }
}

const result = divide(10, 0)
if (result.success) {
  console.log(result.data)  // ✅ Type is number
} else {
  console.error(result.error)  // ✅ Type is string
}
```
