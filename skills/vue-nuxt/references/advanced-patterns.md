# Vue/Nuxt Advanced Patterns

## Complex State Management Patterns

### Nested Reactive State

```typescript
// composables/useHUDState.ts
import { reactive, toRefs } from 'vue'

interface HUDState {
  panels: Map<string, PanelConfig>
  activePanel: string | null
  metrics: SystemMetrics
}

export function useHUDState() {
  const state = reactive<HUDState>({
    panels: new Map(),
    activePanel: null,
    metrics: { cpu: 0, memory: 0, network: 0 }
  })

  const setActivePanel = (id: string) => {
    if (state.panels.has(id)) {
      state.activePanel = id
    }
  }

  return {
    ...toRefs(state),
    setActivePanel
  }
}
```

### Async Component Loading with Error Boundaries

```vue
<script setup lang="ts">
const HeavyComponent = defineAsyncComponent({
  loader: () => import('@/components/Heavy3DScene.vue'),
  loadingComponent: LoadingSpinner,
  errorComponent: ErrorDisplay,
  delay: 200,
  timeout: 10000,
  onError(error, retry, fail) {
    console.error('Component load failed:', error)
    if (error.message.includes('network')) {
      retry()
    } else {
      fail()
    }
  }
})
</script>
```

## Server-Side Rendering Patterns

### Hybrid SSR/CSR for 3D Content

```vue
<script setup lang="ts">
// 3D content should render client-side only
const TresCanvas = defineAsyncComponent(() =>
  import('@tresjs/core').then(m => m.TresCanvas)
)

// Server-safe computed data
const serverData = await useAsyncData('metrics',
  () => $fetch('/api/metrics')
)
</script>

<template>
  <div>
    <!-- SSR-safe content -->
    <MetricsDisplay :data="serverData.data.value" />

    <!-- Client-only 3D rendering -->
    <ClientOnly>
      <TresCanvas>
        <HUD3DScene />
      </TresCanvas>
    </ClientOnly>
  </div>
</template>
```

## Performance Optimization Patterns

### Virtual Scrolling for Large Lists

```vue
<script setup lang="ts">
import { useVirtualList } from '@vueuse/core'

const props = defineProps<{
  items: LogEntry[]
}>()

const { list, containerProps, wrapperProps } = useVirtualList(
  computed(() => props.items),
  { itemHeight: 40 }
)
</script>

<template>
  <div v-bind="containerProps" class="h-96 overflow-auto">
    <div v-bind="wrapperProps">
      <LogRow v-for="item in list" :key="item.index" :data="item.data" />
    </div>
  </div>
</template>
```

### Debounced Watchers

```typescript
import { watchDebounced } from '@vueuse/core'

watchDebounced(
  searchQuery,
  async (query) => {
    if (query.length >= 3) {
      results.value = await $fetch(`/api/search?q=${encodeURIComponent(query)}`)
    }
  },
  { debounce: 300 }
)
```
