# Security Best Practices for Vue 3 & Nuxt 3

This document provides comprehensive security guidance for Vue 3 and Nuxt 3 applications.

## Table of Contents

1. [OWASP Top 10 Coverage](#owasp-top-10-coverage)
2. [XSS Prevention](#xss-prevention)
3. [Content Security Policy (CSP)](#content-security-policy-csp)
4. [Input Validation & Sanitization](#input-validation--sanitization)
5. [Authentication & Authorization](#authentication--authorization)
6. [CSRF Protection](#csrf-protection)
7. [Secure Data Storage](#secure-data-storage)
8. [API Security](#api-security)
9. [Dependency Security](#dependency-security)
10. [Security Headers](#security-headers)

---

## OWASP Top 10 Coverage

### A01:2021 - Broken Access Control

**Risk**: Users can access resources or perform actions they shouldn't be authorized for.

**Examples in Vue/Nuxt:**

```typescript
// ❌ WRONG: Client-side only authorization
// components/AdminPanel.vue
<script setup lang="ts">
const userStore = useUserStore()

// This can be bypassed by modifying client code!
if (!userStore.isAdmin) {
  navigateTo('/')
}
</script>

// ✅ CORRECT: Server-side authorization
// server/api/admin/users.get.ts
export default defineEventHandler(async (event) => {
  // Always check on server
  const user = await requireAdmin(event)

  const users = await db.users.findMany()
  return users
})

// middleware/auth.global.ts
export default defineNuxtRouteMiddleware(async (to) => {
  // Client-side check for UX (shows/hides UI)
  const userStore = useUserStore()

  if (to.path.startsWith('/admin') && !userStore.isAdmin) {
    return navigateTo('/forbidden')
  }
})

// server/utils/auth.ts
export async function requireAdmin(event: H3Event) {
  const session = await getUserSession(event)

  if (!session.user?.roles.includes('admin')) {
    throw createError({
      statusCode: 403,
      message: 'Admin access required'
    })
  }

  return session.user
}
```

**Row-Level Security Example:**

```typescript
// server/api/posts/[id].get.ts
export default defineEventHandler(async (event) => {
  const user = await requireUser(event)
  const postId = getRouterParam(event, 'id')

  const post = await db.post.findUnique({
    where: { id: postId }
  })

  if (!post) {
    throw createError({ statusCode: 404, message: 'Post not found' })
  }

  // ✅ Check if user owns the post or is admin
  if (post.authorId !== user.id && !user.roles.includes('admin')) {
    throw createError({
      statusCode: 403,
      message: 'Not authorized to view this post'
    })
  }

  return post
})
```

### A02:2021 - Cryptographic Failures

**Risk**: Sensitive data exposed due to weak encryption or transmission over HTTP.

**Examples:**

```typescript
// ✅ CORRECT: Enforce HTTPS
// nuxt.config.ts
export default defineNuxtConfig({
  runtimeConfig: {
    public: {
      siteUrl: process.env.SITE_URL || 'https://example.com'
    }
  },

  // Development only - redirect to HTTPS in production
  routeRules: {
    '/**': {
      headers: {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
      }
    }
  }
})

// ✅ CORRECT: Hash passwords server-side
// server/api/auth/register.post.ts
import bcrypt from 'bcrypt'

export default defineEventHandler(async (event) => {
  const { email, password } = await readBody(event)

  // Hash password before storing
  const hashedPassword = await bcrypt.hash(password, 12)

  const user = await db.user.create({
    data: {
      email,
      password: hashedPassword
    }
  })

  return { id: user.id, email: user.email }
})

// ✅ CORRECT: Encrypt sensitive data at rest
import crypto from 'crypto'

const algorithm = 'aes-256-gcm'
const key = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex')

export function encrypt(text: string): string {
  const iv = crypto.randomBytes(16)
  const cipher = crypto.createCipheriv(algorithm, key, iv)

  let encrypted = cipher.update(text, 'utf8', 'hex')
  encrypted += cipher.final('hex')

  const authTag = cipher.getAuthTag()

  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`
}

export function decrypt(encrypted: string): string {
  const [ivHex, authTagHex, encryptedText] = encrypted.split(':')

  const iv = Buffer.from(ivHex, 'hex')
  const authTag = Buffer.from(authTagHex, 'hex')

  const decipher = crypto.createDecipheriv(algorithm, key, iv)
  decipher.setAuthTag(authTag)

  let decrypted = decipher.update(encryptedText, 'hex', 'utf8')
  decrypted += decipher.final('utf8')

  return decrypted
}
```

### A03:2021 - Injection

**Risk**: Attackers inject malicious code through user inputs.

**SQL Injection Prevention:**

```typescript
// ❌ WRONG: Raw SQL with string concatenation
export default defineEventHandler(async (event) => {
  const { username } = getQuery(event)

  // NEVER DO THIS!
  const users = await db.$queryRaw`SELECT * FROM users WHERE username = '${username}'`
})

// ✅ CORRECT: Use parameterized queries with Prisma
export default defineEventHandler(async (event) => {
  const { username } = getQuery(event)

  const users = await db.user.findMany({
    where: {
      username: username as string
    }
  })

  return users
})

// ✅ CORRECT: If using raw SQL, use parameters
export default defineEventHandler(async (event) => {
  const { username } = getQuery(event)

  const users = await db.$queryRaw`
    SELECT * FROM users WHERE username = ${username}
  `

  return users
})
```

**NoSQL Injection Prevention:**

```typescript
// ❌ WRONG: Directly using user input in queries
const { filter } = await readBody(event)
const results = await mongodb.collection.find(filter) // Dangerous!

// ✅ CORRECT: Validate and sanitize input
import { z } from 'zod'

const filterSchema = z.object({
  status: z.enum(['active', 'inactive', 'pending']),
  category: z.string().max(50)
})

export default defineEventHandler(async (event) => {
  const body = await readBody(event)
  const filter = filterSchema.parse(body)

  const results = await mongodb.collection.find(filter)
  return results
})
```

### A04:2021 - Insecure Design

**Risk**: Application designed without security in mind.

**Examples:**

```typescript
// ✅ Security by design: Rate limiting
// server/middleware/rate-limit.ts
import { createError } from 'h3'

const requests = new Map<string, { count: number; resetAt: number }>()

export default defineEventHandler((event) => {
  const ip = getRequestIP(event)
  const now = Date.now()
  const windowMs = 15 * 60 * 1000 // 15 minutes
  const maxRequests = 100

  let record = requests.get(ip)

  if (!record || now > record.resetAt) {
    record = { count: 1, resetAt: now + windowMs }
    requests.set(ip, record)
  } else {
    record.count++

    if (record.count > maxRequests) {
      throw createError({
        statusCode: 429,
        message: 'Too many requests'
      })
    }
  }
})

// ✅ Security by design: Input validation at boundaries
// server/api/users/create.post.ts
import { z } from 'zod'

const createUserSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(12).max(128),
  name: z.string().min(2).max(100),
  age: z.number().int().min(18).max(120).optional()
})

export default defineEventHandler(async (event) => {
  const body = await readBody(event)

  // Validate at API boundary
  const validated = createUserSchema.parse(body)

  // Additional business logic validation
  const existingUser = await db.user.findUnique({
    where: { email: validated.email }
  })

  if (existingUser) {
    throw createError({
      statusCode: 409,
      message: 'Email already registered'
    })
  }

  // Proceed with user creation
  const user = await createUser(validated)
  return user
})
```

### A05:2021 - Security Misconfiguration

**Risk**: Insecure default configurations, incomplete setups, open cloud storage.

**Examples:**

```typescript
// ✅ CORRECT: Secure Nuxt configuration
// nuxt.config.ts
export default defineNuxtConfig({
  runtimeConfig: {
    // Server-only secrets
    databaseUrl: process.env.DATABASE_URL,
    jwtSecret: process.env.JWT_SECRET,
    stripeSecretKey: process.env.STRIPE_SECRET_KEY,

    public: {
      // Only expose what's needed on client
      apiBase: process.env.API_BASE || '/api',
      environment: process.env.NODE_ENV
    }
  },

  nitro: {
    // Disable source maps in production
    sourceMap: process.env.NODE_ENV !== 'production',

    // Enable compression
    compressPublicAssets: true,

    // Security headers
    routeRules: {
      '/**': {
        headers: {
          'X-Frame-Options': 'DENY',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'strict-origin-when-cross-origin',
          'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
        }
      }
    }
  },

  // Disable devtools in production
  devtools: { enabled: process.env.NODE_ENV !== 'production' },

  // Disable telemetry
  telemetry: false
})

// ✅ Environment variable validation
// server/utils/config.ts
import { z } from 'zod'

const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  NODE_ENV: z.enum(['development', 'production', 'test'])
})

export function validateEnv() {
  const result = envSchema.safeParse(process.env)

  if (!result.success) {
    console.error('Invalid environment variables:', result.error.format())
    process.exit(1)
  }

  return result.data
}
```

### A06:2021 - Vulnerable and Outdated Components

**Risk**: Using components with known vulnerabilities.

**Prevention:**

```bash
# Regular dependency audits
npm audit
npm audit fix

# Or with pnpm
pnpm audit
pnpm audit --fix

# Use tools like Snyk
npx snyk test
npx snyk monitor

# Automated dependency updates
npx npm-check-updates -u
```

```json
// package.json - Use exact versions for critical dependencies
{
  "dependencies": {
    "vue": "3.4.21",
    "nuxt": "3.10.3"
  },
  "scripts": {
    "audit": "npm audit",
    "audit:fix": "npm audit fix",
    "check-updates": "npx npm-check-updates"
  }
}
```

### A07:2021 - Identification and Authentication Failures

**Risk**: Weak authentication allowing attackers to compromise accounts.

**Examples:**

```typescript
// ✅ CORRECT: Secure session management
// server/api/auth/login.post.ts
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string()
})

export default defineEventHandler(async (event) => {
  const body = await readBody(event)
  const { email, password } = loginSchema.parse(body)

  // Find user
  const user = await db.user.findUnique({
    where: { email }
  })

  if (!user) {
    // Generic error to prevent email enumeration
    throw createError({
      statusCode: 401,
      message: 'Invalid credentials'
    })
  }

  // Verify password
  const validPassword = await bcrypt.compare(password, user.password)

  if (!validPassword) {
    // Log failed attempt
    await logFailedLogin(user.id, getRequestIP(event))

    throw createError({
      statusCode: 401,
      message: 'Invalid credentials'
    })
  }

  // Generate secure session token
  const token = jwt.sign(
    { userId: user.id, email: user.email },
    process.env.JWT_SECRET!,
    { expiresIn: '7d' }
  )

  // Set httpOnly cookie
  setCookie(event, 'auth_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 24 * 7 // 7 days
  })

  return {
    user: {
      id: user.id,
      email: user.email,
      name: user.name
    }
  }
})

// ✅ Multi-factor authentication
// server/api/auth/verify-2fa.post.ts
import speakeasy from 'speakeasy'

export default defineEventHandler(async (event) => {
  const { userId, token } = await readBody(event)

  const user = await db.user.findUnique({
    where: { id: userId }
  })

  if (!user || !user.twoFactorSecret) {
    throw createError({ statusCode: 400 })
  }

  const verified = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token
  })

  if (!verified) {
    throw createError({
      statusCode: 401,
      message: 'Invalid 2FA token'
    })
  }

  // Mark session as fully authenticated
  await updateSession(event, { twoFactorVerified: true })

  return { success: true }
})
```

### A08:2021 - Software and Data Integrity Failures

**Risk**: Code or infrastructure that doesn't protect against integrity violations.

**Examples:**

```typescript
// ✅ CORRECT: Verify webhook signatures
// server/api/webhooks/stripe.post.ts
import Stripe from 'stripe'

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)

export default defineEventHandler(async (event) => {
  const body = await readRawBody(event)
  const signature = getHeader(event, 'stripe-signature')

  if (!signature || !body) {
    throw createError({ statusCode: 400 })
  }

  try {
    // Verify webhook signature
    const stripeEvent = stripe.webhooks.constructEvent(
      body,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET!
    )

    // Process verified webhook
    await processStripeWebhook(stripeEvent)

    return { received: true }
  } catch (err) {
    console.error('Webhook signature verification failed:', err)
    throw createError({ statusCode: 400, message: 'Invalid signature' })
  }
})

// ✅ CORRECT: Use Subresource Integrity for CDN assets
// nuxt.config.ts
export default defineNuxtConfig({
  app: {
    head: {
      script: [
        {
          src: 'https://cdn.example.com/library.js',
          integrity: 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC',
          crossorigin: 'anonymous'
        }
      ]
    }
  }
})
```

### A09:2021 - Security Logging and Monitoring Failures

**Risk**: Insufficient logging makes it hard to detect breaches.

**Examples:**

```typescript
// ✅ CORRECT: Comprehensive security logging
// server/utils/logger.ts
import winston from 'winston'

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'security.log', level: 'warn' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
})

export function logSecurityEvent(event: {
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  userId?: string
  ip?: string
  details: Record<string, any>
}) {
  logger.warn('Security event', {
    timestamp: new Date().toISOString(),
    ...event
  })
}

// Usage in API routes
export default defineEventHandler(async (event) => {
  try {
    // ... authentication logic
  } catch (error) {
    logSecurityEvent({
      type: 'failed_login',
      severity: 'medium',
      ip: getRequestIP(event),
      details: { email: body.email }
    })
    throw error
  }
})
```

### A10:2021 - Server-Side Request Forgery (SSRF)

**Risk**: Application fetches remote resources without validating user-supplied URLs.

**Examples:**

```typescript
// ❌ WRONG: Fetching arbitrary URLs
export default defineEventHandler(async (event) => {
  const { url } = await readBody(event)

  // Dangerous! User can access internal services
  const response = await fetch(url)
  return response.json()
})

// ✅ CORRECT: Whitelist allowed domains
const ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

export default defineEventHandler(async (event) => {
  const { url } = await readBody(event)

  try {
    const urlObj = new URL(url)

    // Validate domain
    if (!ALLOWED_DOMAINS.includes(urlObj.hostname)) {
      throw createError({
        statusCode: 400,
        message: 'Invalid URL domain'
      })
    }

    // Prevent access to private IPs
    const ip = await resolveHostname(urlObj.hostname)
    if (isPrivateIP(ip)) {
      throw createError({
        statusCode: 400,
        message: 'Access to private IPs not allowed'
      })
    }

    const response = await fetch(url, {
      timeout: 5000,
      headers: { 'User-Agent': 'YourApp/1.0' }
    })

    return response.json()
  } catch (error) {
    throw createError({ statusCode: 400, message: 'Invalid URL' })
  }
})

function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number)

  return (
    parts[0] === 10 ||
    parts[0] === 127 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168)
  )
}
```

---

## XSS Prevention

### Template-Based XSS Prevention

```vue
<script setup lang="ts">
const userInput = ref('<img src=x onerror=alert("XSS")>')
const htmlContent = ref('<p>Some <strong>HTML</strong> content</p>')
</script>

<template>
  <!-- ✅ SAFE: Vue automatically escapes -->
  <div>{{ userInput }}</div>

  <!-- ✅ SAFE: Attributes are escaped -->
  <input :value="userInput" />

  <!-- ❌ DANGEROUS: v-html with user input -->
  <!-- <div v-html="userInput"></div> -->

  <!-- ✅ SAFE: Sanitize before using v-html -->
  <div v-html="$sanitize(htmlContent)"></div>
</template>
```

### DOMPurify Integration

```typescript
// plugins/sanitize.ts
import DOMPurify from 'isomorphic-dompurify'

export default defineNuxtPlugin(() => {
  return {
    provide: {
      sanitize: (dirty: string, config?: DOMPurify.Config) => {
        return DOMPurify.sanitize(dirty, {
          ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'a'],
          ALLOWED_ATTR: ['href', 'target', 'rel'],
          ...config
        })
      }
    }
  }
})
```

---

## Content Security Policy (CSP)

```typescript
// nuxt.config.ts
export default defineNuxtConfig({
  nitro: {
    routeRules: {
      '/**': {
        headers: {
          'Content-Security-Policy': [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.example.com",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "img-src 'self' data: https:",
            "font-src 'self' https://fonts.gstatic.com",
            "connect-src 'self' https://api.example.com",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'"
          ].join('; ')
        }
      }
    }
  }
})
```

---

## Input Validation & Sanitization

### Comprehensive Validation Example

```typescript
// server/api/users/profile.patch.ts
import { z } from 'zod'
import DOMPurify from 'isomorphic-dompurify'

const profileSchema = z.object({
  name: z.string()
    .min(2, 'Name too short')
    .max(100, 'Name too long')
    .regex(/^[a-zA-Z\s'-]+$/, 'Invalid characters in name'),

  bio: z.string()
    .max(500, 'Bio too long')
    .transform(val => DOMPurify.sanitize(val)),

  website: z.string()
    .url('Invalid URL')
    .refine(url => {
      const domain = new URL(url).hostname
      return !isPrivateIP(domain)
    }, 'Private IPs not allowed'),

  age: z.number()
    .int()
    .min(13, 'Must be at least 13')
    .max(120, 'Invalid age'),

  email: z.string()
    .email('Invalid email')
    .transform(val => val.toLowerCase().trim())
})

export default defineEventHandler(async (event) => {
  const user = await requireUser(event)
  const body = await readBody(event)

  // Validate and sanitize
  const validated = profileSchema.parse(body)

  // Update profile
  const updated = await db.user.update({
    where: { id: user.id },
    data: validated
  })

  return updated
})
```

---

## Conclusion

Security is not a one-time task but an ongoing process. Always:

1. **Validate all inputs** on both client and server
2. **Escape all outputs** to prevent XSS
3. **Use HTTPS** everywhere
4. **Keep dependencies updated**
5. **Implement proper authentication** and authorization
6. **Log security events** for monitoring
7. **Set security headers** (CSP, HSTS, etc.)
8. **Follow the principle of least privilege**

For more implementation patterns, see [advanced-patterns.md](./advanced-patterns.md).
