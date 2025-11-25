# Pinia Advanced Patterns

## Plugin Development

### Persistence Plugin

```typescript
// plugins/piniaLogger.ts
import { PiniaPluginContext } from 'pinia'

export function piniaLogger({ store }: PiniaPluginContext) {
  store.$subscribe((mutation, state) => {
    console.log(`[${store.$id}] ${mutation.type}`, {
      storeId: mutation.storeId,
      payload: mutation.payload
    })
  })
}

// Usage
const pinia = createPinia()
pinia.use(piniaLogger)
```

## State Hydration for SSR

```typescript
// plugins/piniaHydration.ts
export function hydrateStores(pinia: Pinia) {
  if (import.meta.server) return

  // Hydrate from SSR payload
  const nuxtApp = useNuxtApp()
  if (nuxtApp.payload.pinia) {
    pinia.state.value = nuxtApp.payload.pinia
  }
}
```

## Optimistic Updates

```typescript
export const useItemsStore = defineStore('items', () => {
  const items = ref<Item[]>([])

  async function deleteItem(id: string) {
    // Save original for rollback
    const original = [...items.value]
    const index = items.value.findIndex(i => i.id === id)

    // Optimistic update
    items.value.splice(index, 1)

    try {
      await $fetch(`/api/items/${id}`, { method: 'DELETE' })
    } catch (error) {
      // Rollback on error
      items.value = original
      throw error
    }
  }

  return { items, deleteItem }
})
```

## Computed with Parameters

```typescript
export const useFilterStore = defineStore('filter', () => {
  const items = ref<Item[]>([])

  // Getter that returns a function
  const getByCategory = computed(() => {
    return (category: string) =>
      items.value.filter(item => item.category === category)
  })

  // Usage: store.getByCategory('electronics')
  return { items, getByCategory }
})
```

## Real-Time Sync

```typescript
export const useRealtimeStore = defineStore('realtime', () => {
  const data = ref<RealtimeData | null>(null)
  let socket: WebSocket | null = null

  function connect() {
    socket = new WebSocket('wss://api.example.com/ws')

    socket.onmessage = (event) => {
      const message = JSON.parse(event.data)
      if (message.type === 'update') {
        data.value = message.data
      }
    }
  }

  function disconnect() {
    socket?.close()
    socket = null
  }

  return { data, connect, disconnect }
})
```
