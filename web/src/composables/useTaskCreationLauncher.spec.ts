import { flushPromises, mount } from '@vue/test-utils'
import { defineComponent } from 'vue'
import { describe, expect, it } from 'vitest'
import { createMemoryHistory, createRouter } from 'vue-router'

import { useTaskCreationLauncher } from '@/composables/useTaskCreationLauncher'

const Harness = defineComponent({
  setup() {
    return useTaskCreationLauncher()
  },
  template: '<button @click="launchTaskCreation">launch</button>',
})

async function harness(path = '/tasks') {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', name: 'overview', component: Harness },
      { path: '/tasks', name: 'tasks', component: Harness },
      { path: '/tasks/new', name: 'task-create', component: Harness },
    ],
  })
  await router.push(path)
  await router.isReady()
  return {
    router,
    wrapper: mount(Harness, { global: { plugins: [router] } }),
  }
}

describe('useTaskCreationLauncher', () => {
  it('opens one uncategorized route and records its return location', async () => {
    const { router, wrapper } = await harness('/tasks?status=FAILED')

    await wrapper.get('button').trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.name).toBe('task-create')
    expect(router.currentRoute.value.query).toEqual({
      return_to: '/tasks?status=FAILED',
    })
    expect(router.currentRoute.value.query.category).toBeUndefined()
  })

  it('does not clear an active categorized creation route', async () => {
    const { router, wrapper } = await harness('/tasks/new?category=container')

    await wrapper.get('button').trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.query.category).toBe('container')
  })
})
