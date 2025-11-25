# Tailwind CSS Advanced Patterns

## Complex Layouts

### HUD Dashboard Grid

```vue
<template>
  <div class="
    grid
    grid-cols-12
    gap-4
    h-screen
    p-4
    bg-jarvis-bg-dark
  ">
    <!-- Top status bar -->
    <div class="col-span-12 h-12 flex items-center justify-between">
      <StatusIndicators />
      <SystemTime />
    </div>

    <!-- Left sidebar -->
    <div class="col-span-2 space-y-4">
      <NavigationPanel />
      <QuickActions />
    </div>

    <!-- Main content -->
    <div class="col-span-7 flex flex-col gap-4">
      <MainDisplay class="flex-1" />
      <BottomControls />
    </div>

    <!-- Right sidebar -->
    <div class="col-span-3 space-y-4">
      <MetricsPanel />
      <AlertsPanel />
    </div>
  </div>
</template>
```

## Custom Animations

### Glitch Effect

```javascript
// tailwind.config.js
animation: {
  'glitch': 'glitch 1s infinite linear alternate-reverse',
  'glitch-1': 'glitch-1 0.8s infinite linear alternate-reverse',
  'glitch-2': 'glitch-2 0.9s infinite linear alternate-reverse'
},
keyframes: {
  glitch: {
    '0%, 100%': { transform: 'translate(0)' },
    '20%': { transform: 'translate(-2px, 2px)' },
    '40%': { transform: 'translate(-2px, -2px)' },
    '60%': { transform: 'translate(2px, 2px)' },
    '80%': { transform: 'translate(2px, -2px)' }
  },
  'glitch-1': {
    '0%, 100%': { clipPath: 'inset(0 0 0 0)' },
    '50%': { clipPath: 'inset(5% 0 80% 0)' }
  }
}
```

## Responsive HUD

```vue
<template>
  <div class="
    flex
    flex-col md:flex-row
    gap-4
    p-2 md:p-4
  ">
    <!-- Collapses on mobile -->
    <aside class="
      w-full md:w-64
      flex md:flex-col
      gap-2
      overflow-x-auto md:overflow-visible
    ">
      <MiniPanel v-for="panel in panels" :key="panel.id" />
    </aside>

    <!-- Main content expands -->
    <main class="flex-1 min-h-[300px] md:min-h-[500px]">
      <slot />
    </main>
  </div>
</template>
```

## Plugin: Holographic Glow

```javascript
// plugins/holographic.js
const plugin = require('tailwindcss/plugin')

module.exports = plugin(function({ addUtilities, theme }) {
  const glows = {}

  Object.entries(theme('colors.jarvis')).forEach(([name, color]) => {
    if (typeof color === 'string') {
      glows[`.glow-${name}`] = {
        boxShadow: `0 0 10px ${color}, 0 0 20px ${color}40, 0 0 30px ${color}20`
      }
      glows[`.text-glow-${name}`] = {
        textShadow: `0 0 10px ${color}`
      }
    }
  })

  addUtilities(glows)
})
```
