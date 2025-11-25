# Advanced Vue 3 & Nuxt 3 Patterns

This document contains advanced implementation patterns for Vue 3 and Nuxt 3 applications.

## Table of Contents

1. [Advanced Composables](#advanced-composables)
2. [Nuxt Plugins](#nuxt-plugins)
3. [Nuxt Modules](#nuxt-modules)
4. [SSR/SSG Advanced Patterns](#ssrssg-advanced-patterns)
5. [Performance Optimization](#performance-optimization)
6. [Advanced State Management](#advanced-state-management)
7. [Component Patterns](#component-patterns)

---

## Advanced Composables

### Composable with Dependency Injection

**Create composables that work with Vue's provide/inject:**

```typescript
// composables/useTheme.ts
import { inject, provide, ref, computed, type Ref, type InjectionKey } from 'vue'

export type Theme = 'light' | 'dark' | 'auto'

interface ThemeContext {
  theme: Ref<Theme>
  isDark: Ref<boolean>
  setTheme: (newTheme: Theme) => void
}

const ThemeSymbol: InjectionKey<ThemeContext> = Symbol('theme')

export function provideTheme() {
  const theme = ref<Theme>('auto')
  const systemPrefersDark = useMediaQuery('(prefers-color-scheme: dark)')

  const isDark = computed(() => {
    if (theme.value === 'auto') {
      return systemPrefersDark.value
    }
    return theme.value === 'dark'
  })

  const setTheme = (newTheme: Theme) => {
    theme.value = newTheme
    if (process.client) {
      localStorage.setItem('theme', newTheme)
      document.documentElement.setAttribute('data-theme', isDark.value ? 'dark' : 'light')
    }
  }

  const context: ThemeContext = {
    theme,
    isDark,
    setTheme
  }

  provide(ThemeSymbol, context)
  return context
}

export function useTheme() {
  const context = inject(ThemeSymbol)
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider')
  }
  return context
}
```

**Usage:**

```vue
<!-- app.vue -->
<script setup lang="ts">
const theme = provideTheme()
</script>

<!-- Any child component -->
<script setup lang="ts">
const { isDark, setTheme } = useTheme()
</script>
```

### Lifecycle-Aware Composable

**Composable that handles cleanup automatically:**

```typescript
// composables/useWebSocket.ts
import { ref, onUnmounted, type Ref } from 'vue'

export interface UseWebSocketOptions {
  onMessage?: (event: MessageEvent) => void
  onError?: (event: Event) => void
  onOpen?: (event: Event) => void
  onClose?: (event: CloseEvent) => void
  reconnect?: boolean
  reconnectInterval?: number
}

export function useWebSocket(url: string, options: UseWebSocketOptions = {}) {
  const {
    onMessage,
    onError,
    onOpen,
    onClose,
    reconnect = true,
    reconnectInterval = 3000
  } = options

  const ws: Ref<WebSocket | null> = ref(null)
  const isConnected = ref(false)
  const reconnectTimer: Ref<NodeJS.Timeout | null> = ref(null)

  const connect = () => {
    if (ws.value) {
      ws.value.close()
    }

    ws.value = new WebSocket(url)

    ws.value.onopen = (event) => {
      isConnected.value = true
      onOpen?.(event)
    }

    ws.value.onmessage = (event) => {
      onMessage?.(event)
    }

    ws.value.onerror = (event) => {
      onError?.(event)
    }

    ws.value.onclose = (event) => {
      isConnected.value = false
      onClose?.(event)

      if (reconnect && !event.wasClean) {
        reconnectTimer.value = setTimeout(() => {
          console.log('Reconnecting WebSocket...')
          connect()
        }, reconnectInterval)
      }
    }
  }

  const send = (data: string | ArrayBuffer | Blob) => {
    if (ws.value && isConnected.value) {
      ws.value.send(data)
    } else {
      console.error('WebSocket is not connected')
    }
  }

  const close = () => {
    if (reconnectTimer.value) {
      clearTimeout(reconnectTimer.value)
    }
    if (ws.value) {
      ws.value.close()
    }
  }

  // Auto-connect
  if (process.client) {
    connect()
  }

  // Auto-cleanup
  onUnmounted(() => {
    close()
  })

  return {
    ws,
    isConnected,
    send,
    close,
    connect
  }
}
```

### Async Composable with AbortController

**Handle cancellable async operations:**

```typescript
// composables/useAbortableFetch.ts
import { ref, onUnmounted, type Ref } from 'vue'

export function useAbortableFetch<T>() {
  const data: Ref<T | null> = ref(null)
  const error: Ref<Error | null> = ref(null)
  const loading = ref(false)
  const abortController: Ref<AbortController | null> = ref(null)

  const execute = async (url: string, options: RequestInit = {}) => {
    // Abort previous request
    if (abortController.value) {
      abortController.value.abort()
    }

    abortController.value = new AbortController()
    loading.value = true
    error.value = null

    try {
      const response = await fetch(url, {
        ...options,
        signal: abortController.value.signal
      })

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }

      data.value = await response.json()
    } catch (e) {
      if (e instanceof Error && e.name !== 'AbortError') {
        error.value = e
      }
    } finally {
      loading.value = false
    }
  }

  const abort = () => {
    if (abortController.value) {
      abortController.value.abort()
    }
  }

  onUnmounted(() => {
    abort()
  })

  return { data, error, loading, execute, abort }
}
```

---

## Nuxt Plugins

### Global Error Handler Plugin

```typescript
// plugins/error-handler.ts
export default defineNuxtPlugin((nuxtApp) => {
  nuxtApp.vueApp.config.errorHandler = (error, instance, info) => {
    console.error('Global error:', error)
    console.error('Component:', instance)
    console.error('Info:', info)

    // Send to error tracking service
    if (process.client) {
      // Example: Sentry, LogRocket, etc.
      window.errorTracker?.captureException(error, {
        extra: { info, component: instance?.$options.name }
      })
    }
  }

  // Handle Vue warnings
  nuxtApp.vueApp.config.warnHandler = (msg, instance, trace) => {
    console.warn('Vue warning:', msg)
    console.warn('Trace:', trace)
  }
})
```

### API Client Plugin with Interceptors

```typescript
// plugins/api.ts
import type { FetchContext } from 'ofetch'

export default defineNuxtPlugin(() => {
  const config = useRuntimeConfig()
  const userStore = useUserStore()

  const api = $fetch.create({
    baseURL: config.public.apiBase,

    // Request interceptor
    async onRequest({ request, options }: FetchContext) {
      // Add auth token
      const token = userStore.token
      if (token) {
        options.headers = {
          ...options.headers,
          Authorization: `Bearer ${token}`
        }
      }

      // Add request ID for tracing
      options.headers = {
        ...options.headers,
        'X-Request-ID': crypto.randomUUID()
      }

      console.log('[API Request]', request)
    },

    // Response interceptor
    async onResponse({ response }: FetchContext) {
      console.log('[API Response]', response.status, response._data)
    },

    // Error interceptor
    async onResponseError({ request, response }: FetchContext) {
      console.error('[API Error]', request, response.status, response._data)

      // Handle 401 - Unauthorized
      if (response.status === 401) {
        await userStore.logout()
        await navigateTo('/login')
      }

      // Handle 403 - Forbidden
      if (response.status === 403) {
        await navigateTo('/forbidden')
      }

      // Handle 500 - Server Error
      if (response.status >= 500) {
        // Show error notification
        useNotification().error('Server error. Please try again later.')
      }
    }
  })

  return {
    provide: {
      api
    }
  }
})
```

**Usage:**

```vue
<script setup lang="ts">
const { $api } = useNuxtApp()

const fetchUsers = async () => {
  const users = await $api('/users')
  return users
}
</script>
```

### Analytics Plugin

```typescript
// plugins/analytics.client.ts
export default defineNuxtPlugin((nuxtApp) => {
  const router = useRouter()
  const config = useRuntimeConfig()

  // Initialize analytics (e.g., Google Analytics, Plausible)
  const analytics = {
    trackPageView(path: string) {
      if (config.public.analyticsId) {
        // Example: gtag('config', config.public.analyticsId, { page_path: path })
        console.log('[Analytics] Page view:', path)
      }
    },

    trackEvent(event: string, params?: Record<string, any>) {
      if (config.public.analyticsId) {
        // Example: gtag('event', event, params)
        console.log('[Analytics] Event:', event, params)
      }
    }
  }

  // Track route changes
  router.afterEach((to) => {
    nextTick(() => {
      analytics.trackPageView(to.fullPath)
    })
  })

  return {
    provide: {
      analytics
    }
  }
})
```

---

## Nuxt Modules

### Custom Nuxt Module Structure

```typescript
// modules/custom-analytics/index.ts
import { defineNuxtModule, addPlugin, createResolver } from '@nuxt/kit'

export interface ModuleOptions {
  enabled: boolean
  analyticsId?: string
}

export default defineNuxtModule<ModuleOptions>({
  meta: {
    name: 'custom-analytics',
    configKey: 'customAnalytics',
    compatibility: {
      nuxt: '^3.0.0'
    }
  },

  defaults: {
    enabled: true
  },

  setup(options, nuxt) {
    if (!options.enabled) return

    const resolver = createResolver(import.meta.url)

    // Add runtime config
    nuxt.options.runtimeConfig.public.analyticsId = options.analyticsId

    // Add plugin
    addPlugin(resolver.resolve('./runtime/plugin'))

    console.log(`✓ Custom Analytics Module initialized`)
  }
})
```

---

## SSR/SSG Advanced Patterns

### Hybrid Rendering with Route Rules

```typescript
// nuxt.config.ts
export default defineNuxtConfig({
  routeRules: {
    // Static pages (pre-rendered at build time)
    '/': { prerender: true },
    '/about': { prerender: true },
    '/blog/**': {
      swr: 3600,  // Stale-while-revalidate: cache for 1 hour
      prerender: true
    },

    // Dynamic SSR pages
    '/dashboard/**': { ssr: true },
    '/user/**': { ssr: true },

    // Client-only rendering (SPA mode)
    '/admin/**': { ssr: false },

    // API routes with caching
    '/api/posts': {
      swr: 600,  // Cache for 10 minutes
      headers: {
        'Cache-Control': 'public, max-age=600, s-maxage=600'
      }
    },

    // ISR (Incremental Static Regeneration)
    '/products/**': {
      swr: true,
      prerender: true
    }
  }
})
```

### Server-Only Utils

```typescript
// server/utils/db.ts
import { PrismaClient } from '@prisma/client'

let prisma: PrismaClient

export function usePrisma() {
  if (!prisma) {
    prisma = new PrismaClient()
  }
  return prisma
}

// server/utils/auth.ts
import { H3Event } from 'h3'

export async function requireUser(event: H3Event) {
  const session = await getUserSession(event)

  if (!session.user) {
    throw createError({
      statusCode: 401,
      message: 'Unauthorized'
    })
  }

  return session.user
}

export async function requireAdmin(event: H3Event) {
  const user = await requireUser(event)

  if (!user.roles.includes('admin')) {
    throw createError({
      statusCode: 403,
      message: 'Admin access required'
    })
  }

  return user
}
```

### Page Transitions with View Transitions API

```vue
<!-- app.vue -->
<script setup lang="ts">
const route = useRoute()
</script>

<template>
  <NuxtLayout>
    <NuxtPage :key="route.path" :transition="{
      name: 'page',
      mode: 'out-in',
      onBeforeEnter: (el) => {
        if (document.startViewTransition) {
          document.startViewTransition(() => {})
        }
      }
    }" />
  </NuxtLayout>
</template>

<style>
.page-enter-active,
.page-leave-active {
  transition: opacity 0.3s, transform 0.3s;
}

.page-enter-from {
  opacity: 0;
  transform: translateX(20px);
}

.page-leave-to {
  opacity: 0;
  transform: translateX(-20px);
}

/* View Transitions API */
@supports (view-transition-name: none) {
  ::view-transition-old(root),
  ::view-transition-new(root) {
    animation-duration: 0.3s;
  }
}
</style>
```

---

## Performance Optimization

### Virtual Scrolling for Large Lists

```vue
<script setup lang="ts">
import { useVirtualList } from '@vueuse/core'

interface Item {
  id: number
  name: string
  description: string
}

const allItems = ref<Item[]>(
  Array.from({ length: 10000 }, (_, i) => ({
    id: i,
    name: `Item ${i}`,
    description: `Description for item ${i}`
  }))
)

const { list, containerProps, wrapperProps } = useVirtualList(
  allItems,
  {
    itemHeight: 60,
    overscan: 10
  }
)
</script>

<template>
  <div v-bind="containerProps" style="height: 600px; overflow: auto">
    <div v-bind="wrapperProps">
      <div
        v-for="{ index, data } in list"
        :key="data.id"
        style="height: 60px; border-bottom: 1px solid #eee"
      >
        <h3>{{ data.name }}</h3>
        <p>{{ data.description }}</p>
      </div>
    </div>
  </div>
</template>
```

### Image Optimization with Nuxt Image

```vue
<script setup lang="ts">
const imageUrl = '/images/hero.jpg'
</script>

<template>
  <div>
    <!-- Automatic format optimization (WebP, AVIF) -->
    <NuxtImg
      :src="imageUrl"
      alt="Hero image"
      width="800"
      height="600"
      format="webp"
      quality="80"
      loading="lazy"
      :modifiers="{ fit: 'cover' }"
    />

    <!-- Responsive images with srcset -->
    <NuxtPicture
      :src="imageUrl"
      alt="Responsive hero"
      :img-attrs="{ class: 'responsive-img' }"
      sizes="xs:100vw sm:100vw md:50vw lg:400px xl:400px"
      format="webp"
    />

    <!-- Background image optimization -->
    <div
      class="hero"
      :style="{
        backgroundImage: `url(${$img(imageUrl, { width: 1920, format: 'webp' })})`
      }"
    />
  </div>
</template>
```

### Lazy Hydration for Islands

```vue
<script setup lang="ts">
// Heavy interactive component that doesn't need immediate hydration
const HeavyInteractiveWidget = defineAsyncComponent(() =>
  import('~/components/HeavyInteractiveWidget.vue')
)
</script>

<template>
  <div>
    <!-- Static content hydrates immediately -->
    <header>
      <h1>My Page</h1>
    </header>

    <!-- Heavy component hydrates on idle -->
    <LazyHydrate when-idle>
      <HeavyInteractiveWidget />
    </LazyHydrate>

    <!-- Hydrate when visible -->
    <LazyHydrate when-visible>
      <CommentSection />
    </LazyHydrate>

    <!-- Hydrate on interaction -->
    <LazyHydrate when-triggered>
      <template #default="{ trigger }">
        <button @click="trigger">Load Chat</button>
      </template>
      <ChatWidget />
    </LazyHydrate>
  </div>
</template>
```

---

## Advanced State Management

### Pinia with Persistence

```typescript
// stores/cart.ts
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

export interface CartItem {
  id: string
  name: string
  price: number
  quantity: number
}

export const useCartStore = defineStore('cart', () => {
  const items = ref<CartItem[]>([])

  const total = computed(() =>
    items.value.reduce((sum, item) => sum + item.price * item.quantity, 0)
  )

  const itemCount = computed(() =>
    items.value.reduce((count, item) => count + item.quantity, 0)
  )

  function addItem(product: Omit<CartItem, 'quantity'>) {
    const existing = items.value.find(item => item.id === product.id)

    if (existing) {
      existing.quantity++
    } else {
      items.value.push({ ...product, quantity: 1 })
    }

    persist()
  }

  function removeItem(id: string) {
    const index = items.value.findIndex(item => item.id === id)
    if (index > -1) {
      items.value.splice(index, 1)
      persist()
    }
  }

  function updateQuantity(id: string, quantity: number) {
    const item = items.value.find(item => item.id === id)
    if (item) {
      item.quantity = Math.max(0, quantity)
      if (item.quantity === 0) {
        removeItem(id)
      } else {
        persist()
      }
    }
  }

  function clear() {
    items.value = []
    persist()
  }

  function persist() {
    if (process.client) {
      localStorage.setItem('cart', JSON.stringify(items.value))
    }
  }

  function hydrate() {
    if (process.client) {
      const stored = localStorage.getItem('cart')
      if (stored) {
        try {
          items.value = JSON.parse(stored)
        } catch (e) {
          console.error('Failed to parse cart from localStorage')
        }
      }
    }
  }

  // Hydrate on store creation
  hydrate()

  return {
    items,
    total,
    itemCount,
    addItem,
    removeItem,
    updateQuantity,
    clear
  }
})
```

### Cross-Tab State Synchronization

```typescript
// composables/useCrossTabSync.ts
import { watch, onMounted, onUnmounted } from 'vue'

export function useCrossTabSync<T>(key: string, state: Ref<T>) {
  if (!process.client) return

  const handleStorageChange = (event: StorageEvent) => {
    if (event.key === key && event.newValue) {
      try {
        state.value = JSON.parse(event.newValue)
      } catch (e) {
        console.error('Failed to parse storage event')
      }
    }
  }

  onMounted(() => {
    window.addEventListener('storage', handleStorageChange)
  })

  onUnmounted(() => {
    window.removeEventListener('storage', handleStorageChange)
  })

  watch(state, (newValue) => {
    localStorage.setItem(key, JSON.stringify(newValue))
  }, { deep: true })
}
```

---

## Component Patterns

### Renderless Component Pattern

```vue
<!-- components/MouseTracker.vue -->
<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'

const x = ref(0)
const y = ref(0)

const handleMouseMove = (event: MouseEvent) => {
  x.value = event.clientX
  y.value = event.clientY
}

onMounted(() => {
  window.addEventListener('mousemove', handleMouseMove)
})

onUnmounted(() => {
  window.removeEventListener('mousemove', handleMouseMove)
})

defineSlots<{
  default(props: { x: number; y: number }): any
}>()
</script>

<template>
  <slot :x="x" :y="y" />
</template>
```

**Usage:**

```vue
<template>
  <MouseTracker v-slot="{ x, y }">
    <div>Mouse position: {{ x }}, {{ y }}</div>
  </MouseTracker>
</template>
```

### Headless UI Component

```vue
<!-- components/Tabs.vue -->
<script setup lang="ts">
import { ref, provide, readonly } from 'vue'

const activeTab = ref(0)

const setActiveTab = (index: number) => {
  activeTab.value = index
}

provide('tabsContext', {
  activeTab: readonly(activeTab),
  setActiveTab
})
</script>

<template>
  <div class="tabs">
    <slot />
  </div>
</template>

<!-- components/TabList.vue -->
<script setup lang="ts">
import { inject } from 'vue'

const context = inject('tabsContext')
</script>

<template>
  <div role="tablist" class="tab-list">
    <slot />
  </div>
</template>

<!-- components/Tab.vue -->
<script setup lang="ts">
import { inject, computed } from 'vue'

const props = defineProps<{
  index: number
}>()

const context = inject('tabsContext')
const isActive = computed(() => context.activeTab.value === props.index)

const handleClick = () => {
  context.setActiveTab(props.index)
}
</script>

<template>
  <button
    role="tab"
    :aria-selected="isActive"
    :class="{ active: isActive }"
    @click="handleClick"
  >
    <slot />
  </button>
</template>

<!-- components/TabPanels.vue -->
<template>
  <div class="tab-panels">
    <slot />
  </div>
</template>

<!-- components/TabPanel.vue -->
<script setup lang="ts">
import { inject, computed } from 'vue'

const props = defineProps<{
  index: number
}>()

const context = inject('tabsContext')
const isActive = computed(() => context.activeTab.value === props.index)
</script>

<template>
  <div v-show="isActive" role="tabpanel" class="tab-panel">
    <slot />
  </div>
</template>
```

**Usage:**

```vue
<template>
  <Tabs>
    <TabList>
      <Tab :index="0">Tab 1</Tab>
      <Tab :index="1">Tab 2</Tab>
      <Tab :index="2">Tab 3</Tab>
    </TabList>

    <TabPanels>
      <TabPanel :index="0">Content 1</TabPanel>
      <TabPanel :index="1">Content 2</TabPanel>
      <TabPanel :index="2">Content 3</TabPanel>
    </TabPanels>
  </Tabs>
</template>
```

---

## Conclusion

These advanced patterns demonstrate the flexibility and power of Vue 3 and Nuxt 3. Use them to build scalable, maintainable, and performant applications.

For security best practices, see [security-examples.md](./security-examples.md).
