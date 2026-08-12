/* eslint-disable vue/one-component-per-file */
import { flushPromises, mount } from '@vue/test-utils'
import { defineComponent } from 'vue'
import { describe, expect, it } from 'vitest'
import { createMemoryHistory, createRouter } from 'vue-router'

import CreateTaskView from '@/views/CreateTaskView.vue'

const DialogStub = defineComponent({
  name: 'TaskInputCategoryDialog',
  props: {
    modelValue: Boolean,
    currentCategory: { type: String, default: null },
    required: Boolean,
    locked: Boolean,
  },
  emits: ['update:modelValue', 'select', 'cancel'],
  template: '<div class="dialog-stub" :data-open="modelValue" />',
})

const WorkspaceStub = defineComponent({
  name: 'CategorizedUploadWorkspace',
  props: { category: { type: String, required: true } },
  emits: ['lockChange'],
  template: '<div class="workspace-stub">{{ category }}</div>',
})

const PageHeaderStub = defineComponent({
  name: 'PageHeader',
  template: '<header><slot name="actions" /></header>',
})

const ButtonStub = defineComponent({
  name: 'ElButton',
  inheritAttrs: false,
  props: { disabled: Boolean },
  emits: ['click'],
  template:
    '<button type="button" :disabled="disabled" @click="$emit(\'click\')"><slot /></button>',
})

async function mountView(path: string) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/tasks', name: 'tasks', component: { template: '<div />' } },
      { path: '/tasks/new', name: 'task-create', component: CreateTaskView },
    ],
  })
  await router.push(path)
  await router.isReady()
  const wrapper = mount(CreateTaskView, {
    global: {
      plugins: [router],
      stubs: {
        PageHeader: PageHeaderStub,
        TaskInputCategoryDialog: DialogStub,
        CategorizedUploadWorkspace: WorkspaceStub,
        ElButton: ButtonStub,
      },
    },
  })
  await flushPromises()
  return { wrapper, router }
}

describe('CreateTaskView category routing', () => {
  it('shows only the required dialog when the route has no valid category', async () => {
    const { wrapper } = await mountView('/tasks/new?category=unknown')
    const dialog = wrapper.getComponent(DialogStub)

    expect(dialog.props('modelValue')).toBe(true)
    expect(dialog.props('required')).toBe(true)
    expect(wrapper.findComponent(WorkspaceStub).exists()).toBe(false)
  })

  it('stores a selected category in the route before mounting its workspace', async () => {
    const { wrapper, router } = await mountView('/tasks/new?return_to=/tasks')
    wrapper.getComponent(DialogStub).vm.$emit('select', 'archive')
    await flushPromises()

    expect(router.currentRoute.value.query.category).toBe('archive')
    expect(wrapper.getComponent(WorkspaceStub).props('category')).toBe('archive')
    expect(wrapper.getComponent(DialogStub).props('modelValue')).toBe(false)
  })

  it('locks category switching as soon as the workspace queue is nonempty', async () => {
    const { wrapper, router } = await mountView('/tasks/new?category=binary')
    wrapper.getComponent(WorkspaceStub).vm.$emit('lockChange', true)
    await flushPromises()

    expect(wrapper.get('button').attributes('disabled')).toBeDefined()
    expect(wrapper.getComponent(DialogStub).props('locked')).toBe(true)

    await router.push('/tasks/new?category=container')
    await flushPromises()

    expect(router.currentRoute.value.query.category).toBe('binary')
    expect(wrapper.getComponent(WorkspaceStub).props('category')).toBe('binary')
  })

  it('cancels a direct required dialog back to the tasks page', async () => {
    const { wrapper, router } = await mountView('/tasks/new')
    wrapper.getComponent(DialogStub).vm.$emit('cancel')
    await flushPromises()

    expect(router.currentRoute.value.name).toBe('tasks')
  })
})
