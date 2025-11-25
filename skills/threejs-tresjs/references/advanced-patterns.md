# Three.js/TresJS Advanced Patterns

## Custom Shaders with TresJS

### ShaderMaterial Component

```vue
<script setup lang="ts">
import { shallowRef } from 'vue'
import { ShaderMaterial, Vector2 } from 'three'

const materialRef = shallowRef<ShaderMaterial | null>(null)

const uniforms = {
  uTime: { value: 0 },
  uResolution: { value: new Vector2(window.innerWidth, window.innerHeight) },
  uColor: { value: [0, 1, 0.25] }
}

// Update in render loop
useRenderLoop().onLoop(({ elapsed }) => {
  if (materialRef.value) {
    materialRef.value.uniforms.uTime.value = elapsed
  }
})
</script>

<template>
  <TresMesh>
    <TresPlaneGeometry :args="[2, 2]" />
    <TresShaderMaterial
      ref="materialRef"
      :uniforms="uniforms"
      :vertex-shader="vertexShader"
      :fragment-shader="fragmentShader"
      :transparent="true"
    />
  </TresMesh>
</template>
```

## Post-Processing Effects

### Bloom and Glitch

```vue
<script setup lang="ts">
import { EffectComposer, Bloom, Glitch } from '@tresjs/post-processing'

const bloomOptions = {
  luminanceThreshold: 0.9,
  luminanceSmoothing: 0.3,
  intensity: 1.5
}
</script>

<template>
  <TresCanvas>
    <HUDScene />

    <EffectComposer>
      <Bloom v-bind="bloomOptions" />
      <Glitch :active="glitchActive" :strength="[0.2, 0.4]" />
    </EffectComposer>
  </TresCanvas>
</template>
```

## Physics Integration

### Rapier Physics

```vue
<script setup lang="ts">
import { Physics, RigidBody } from '@tresjs/rapier'
</script>

<template>
  <TresCanvas>
    <Physics :gravity="[0, -9.81, 0]">
      <RigidBody type="fixed">
        <TresMesh :position="[0, -2, 0]">
          <TresBoxGeometry :args="[10, 0.5, 10]" />
          <TresMeshStandardMaterial />
        </TresMesh>
      </RigidBody>

      <RigidBody>
        <TresMesh>
          <TresSphereGeometry />
          <TresMeshStandardMaterial />
        </TresMesh>
      </RigidBody>
    </Physics>
  </TresCanvas>
</template>
```
