# Vue/Nuxt Security Examples

## CVE Mitigations

### CVE-2024-34344 - RCE Prevention

```typescript
// nuxt.config.ts - Secure test configuration
export default defineNuxtConfig({
  // Disable test features in production
  experimental: {
    componentIslands: process.env.NODE_ENV === 'development'
  },

  // Strict CSP for production
  routeRules: {
    '/**': {
      headers: {
        'Content-Security-Policy': [
          "default-src 'self'",
          "script-src 'self'",
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' data: blob:",
          "connect-src 'self' wss:",
          "frame-ancestors 'none'"
        ].join('; ')
      }
    }
  }
})
```

### CVE-2024-23657 - Devtools Security

```typescript
// nuxt.config.ts
export default defineNuxtConfig({
  devtools: {
    enabled: process.env.NODE_ENV === 'development',
    // Never expose devtools WebSocket publicly
  },

  // Production: completely disable
  $production: {
    devtools: { enabled: false }
  }
})
```

## XSS Prevention Patterns

### Comprehensive Sanitization

```typescript
// utils/security.ts
import DOMPurify from 'isomorphic-dompurify'

// Configure DOMPurify for strict sanitization
DOMPurify.setConfig({
  FORBID_TAGS: ['script', 'object', 'embed', 'form', 'input'],
  FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover']
})

export const sanitizers = {
  // For user-generated content that needs minimal HTML
  richText: (dirty: string) => DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['p', 'br', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href', 'title'],
    ALLOW_DATA_ATTR: false
  }),

  // For plain text display
  plainText: (dirty: string) => DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: [],
    KEEP_CONTENT: true
  }),

  // For URLs
  url: (dirty: string) => {
    const sanitized = DOMPurify.sanitize(dirty, { ALLOWED_TAGS: [] })
    // Only allow http/https protocols
    if (!/^https?:\/\//i.test(sanitized)) {
      return ''
    }
    return sanitized
  }
}
```

### Safe Dynamic Component Rendering

```vue
<script setup lang="ts">
// ❌ DANGEROUS - Dynamic component from user input
// <component :is="userInput" />

// ✅ SECURE - Allowlist of valid components
const componentMap = {
  'status-panel': StatusPanel,
  'metrics-display': MetricsDisplay,
  'alert-banner': AlertBanner
} as const

const props = defineProps<{
  componentType: string
}>()

const safeComponent = computed(() => {
  const key = props.componentType as keyof typeof componentMap
  return componentMap[key] || FallbackComponent
})
</script>

<template>
  <component :is="safeComponent" />
</template>
```

## Authentication & Authorization

### Route Protection Middleware

```typescript
// middleware/auth.global.ts
export default defineNuxtRouteMiddleware(async (to) => {
  const { user, refreshToken } = useAuth()

  // Public routes
  if (to.meta.public) return

  // Check authentication
  if (!user.value) {
    // Try to refresh token
    const refreshed = await refreshToken()
    if (!refreshed) {
      return navigateTo({
        path: '/login',
        query: { redirect: to.fullPath }
      })
    }
  }

  // Check authorization
  if (to.meta.requiredRole) {
    if (!user.value?.roles.includes(to.meta.requiredRole)) {
      throw createError({
        statusCode: 403,
        message: 'Insufficient permissions'
      })
    }
  }
})
```

### CSRF Protection for API Routes

```typescript
// server/middleware/csrf.ts
export default defineEventHandler(async (event) => {
  // Skip for GET requests
  if (event.method === 'GET') return

  const csrfToken = getHeader(event, 'x-csrf-token')
  const sessionToken = await getSession(event)

  if (!csrfToken || csrfToken !== sessionToken.csrf) {
    throw createError({
      statusCode: 403,
      message: 'Invalid CSRF token'
    })
  }
})
```

## Rate Limiting

```typescript
// server/utils/rateLimit.ts
const rateLimits = new Map<string, { count: number; resetAt: number }>()

export function checkRateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now()
  const record = rateLimits.get(key)

  if (!record || now > record.resetAt) {
    rateLimits.set(key, { count: 1, resetAt: now + windowMs })
    return true
  }

  if (record.count >= limit) {
    return false
  }

  record.count++
  return true
}

// Usage in API route
export default defineEventHandler(async (event) => {
  const ip = getRequestIP(event) || 'unknown'

  if (!checkRateLimit(`api:${ip}`, 100, 60000)) {
    throw createError({
      statusCode: 429,
      message: 'Too many requests'
    })
  }

  // Process request
})
```
