# Pinia Security Examples

## SSR State Isolation

### Preventing State Leakage

```typescript
// ❌ DANGEROUS - Shared across all requests
// store.ts
let globalData = null

export function getData() {
  return globalData
}

// ✅ SECURE - Per-request isolation
export const useDataStore = defineStore('data', () => {
  // Each request gets fresh state
  const data = ref(null)

  return { data }
})
```

### Nuxt Server-Side Security

```typescript
// server/api/user.ts
export default defineEventHandler(async (event) => {
  // Get user from session, not from client state
  const session = await getSession(event)

  if (!session.user) {
    throw createError({ statusCode: 401 })
  }

  // Never trust state from client
  return { user: session.user }
})
```

## Sensitive Data Protection

### Memory-Only Storage

```typescript
export const useAuthStore = defineStore('auth', () => {
  // Sensitive data - memory only
  const accessToken = ref<string | null>(null)
  const refreshToken = ref<string | null>(null)

  // Non-sensitive - can persist
  const userPreferences = ref({})

  return {
    accessToken,
    refreshToken,
    userPreferences
  }
  // NO persist option for sensitive data
})
```

### Secure Token Handling

```typescript
export const useAuthStore = defineStore('auth', () => {
  const accessToken = ref<string | null>(null)

  async function login(credentials: Credentials) {
    const response = await $fetch('/api/auth/login', {
      method: 'POST',
      body: credentials
    })

    // Token in memory only
    accessToken.value = response.accessToken

    // Set httpOnly cookie on server
    // (handled by server response)
  }

  function logout() {
    // Clear memory
    accessToken.value = null

    // Clear httpOnly cookie
    $fetch('/api/auth/logout', { method: 'POST' })
  }

  return { accessToken, login, logout }
})
```

## Action Validation

### Input Sanitization

```typescript
import { z } from 'zod'

const userUpdateSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  bio: z.string().max(500).optional()
})

export const useUserStore = defineStore('user', () => {
  const user = ref<User | null>(null)

  async function updateUser(updates: unknown) {
    // Validate before mutation
    const validated = userUpdateSchema.parse(updates)

    // Safe to update
    const response = await $fetch('/api/user', {
      method: 'PATCH',
      body: validated
    })

    user.value = response
  }

  return { user, updateUser }
})
```

## Permission Checking

```typescript
export const useAdminStore = defineStore('admin', () => {
  const currentUser = computed(() => useAuthStore().user)

  async function deleteUser(userId: string) {
    // Check permission before action
    if (!currentUser.value?.permissions.includes('admin')) {
      throw new Error('Unauthorized')
    }

    await $fetch(`/api/admin/users/${userId}`, {
      method: 'DELETE'
    })
  }

  return { deleteUser }
})
```
