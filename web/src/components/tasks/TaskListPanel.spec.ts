import { flushPromises, mount } from '@vue/test-utils'
import {
  createMemoryHistory,
  createRouter,
  type Router,
} from 'vue-router'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/api/client'
import type { ScanTask, TaskPage } from '@/api/types'
import TaskListPanel from '@/components/tasks/TaskListPanel.vue'

const FilterStub = {
  name: 'TaskFilterBar',
  props: {
    initialValue: {
      type: Object,
      required: true,
    },
  },
  emits: ['apply', 'reset'],
  template: '<div data-testid="filters" />',
}

const TableStub = {
  name: 'TaskTable',
  props: {
    items: {
      type: Array,
      required: true,
    },
    pageSize: {
      type: Number,
      required: true,
    },
    hasPrevious: Boolean,
    hasNext: Boolean,
    canReset: Boolean,
    loading: Boolean,
    userRole: String,
    currentUserId: String,
    pendingTaskId: String,
  },
  emits: ['open', 'delete', 'firstPage', 'previousPage', 'nextPage', 'pageSizeChange'],
  template: '<div data-testid="task-table">{{ items.length }}</div>',
}

const DeleteDialogStub = {
  name: 'TaskDeleteDialog',
  props: ['modelValue', 'taskName', 'pending', 'errorMessage'],
  emits: ['update:modelValue', 'confirm'],
  template: `
    <div v-if="modelValue" data-testid="delete-dialog">
      <span>{{ taskName }}</span>
      <span>{{ errorMessage }}</span>
      <button data-testid="confirm-delete" @click="$emit('confirm')">confirm</button>
    </div>
  `,
}

const StateStub = {
  name: 'StatePanel',
  props: {
    kind: String,
    title: String,
    description: String,
    retryable: Boolean,
  },
  emits: ['retry'],
  template: '<div data-testid="state">{{ kind }}</div>',
}

function task(overrides: Partial<ScanTask> = {}): ScanTask {
  return {
    id: '10000000-0000-4000-8000-000000000001',
    name: 'firmware',
    input_type: 'elf64',
    status: 'SUCCEEDED',
    risk_level: 'NONE',
    progress: 100,
    creator_id: 'operator-1',
    creator_name: 'operator',
    tags: [],
    created_at: '2026-07-30T00:00:00Z',
    ...overrides,
    progress_indeterminate: overrides.progress_indeterminate ?? false,
    sample_expires_at:
      overrides.sample_expires_at ?? '2099-08-29T00:00:00Z',
    sample_deleted_at: overrides.sample_deleted_at ?? null,
  }
}

function page(items: ScanTask[] = [task()], nextCursor?: string): TaskPage {
  return {
    items,
    ...(nextCursor ? { next_cursor: nextCursor } : {}),
  }
}

function pending<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise
  })
  return { promise, resolve }
}

async function mountPanel(
  path: string,
  props: { userRole?: 'administrator' | 'operator' | 'reader'; currentUserId?: string } = {},
): Promise<{
  router: Router
  wrapper: ReturnType<typeof mount>
}> {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/tasks', component: { template: '<div />' } }],
  })
  await router.push(path)
  await router.isReady()

  const wrapper = mount(TaskListPanel, {
    props,
    global: {
      plugins: [router],
      stubs: {
        TaskFilterBar: FilterStub,
        TaskTable: TableStub,
        TaskDeleteDialog: DeleteDialogStub,
        StatePanel: StateStub,
        ElButton: {
          template: '<button type="button"><slot /></button>',
        },
      },
    },
  })
  await flushPromises()
  await flushPromises()
  return { router, wrapper }
}

describe('TaskListPanel', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('restores exact filters and an opaque cursor from a shareable URL', async () => {
    const listTasks = vi.spyOn(api, 'listTasks').mockResolvedValue(page())
    const { router, wrapper } = await mountPanel(
      '/tasks?keyword=%20firmware%20&status=EXTRACTING&input_type=ELF64' +
        '&creator=%20Demo%20Operator%20&tag=firmware' +
        '&created_from=2026-07-01&created_to=2026-07-30' +
        '&cursor=opaque_cursor-3&page_size=50',
    )

    expect(listTasks).toHaveBeenCalledTimes(1)
    expect(listTasks).toHaveBeenCalledWith({
      keyword: 'firmware',
      status: 'EXTRACTING',
      input_type: 'elf64',
      creator: 'Demo Operator',
      tag: 'firmware',
      created_from: '2026-07-01',
      created_to: '2026-07-30',
      cursor: 'opaque_cursor-3',
      page_size: 50,
    })
    expect(wrapper.getComponent(FilterStub).props('initialValue')).toEqual({
      keyword: 'firmware',
      status: 'EXTRACTING',
      input_type: 'elf64',
      creator: 'Demo Operator',
      tag: 'firmware',
      created_from: '2026-07-01',
      created_to: '2026-07-30',
    })
    expect(wrapper.getComponent(TableStub).props()).toMatchObject({
      pageSize: 50,
      canReset: true,
      hasPrevious: false,
    })
    expect(router.currentRoute.value.query).toEqual({
      keyword: 'firmware',
      status: 'EXTRACTING',
      input_type: 'elf64',
      creator: 'Demo Operator',
      tag: 'firmware',
      created_from: '2026-07-01',
      created_to: '2026-07-30',
      cursor: 'opaque_cursor-3',
      page_size: '50',
    })
  })

  it('canonicalizes invalid URL values to safe defaults without duplicate requests', async () => {
    const listTasks = vi.spyOn(api, 'listTasks').mockResolvedValue(page())
    const { router } = await mountPanel(
      '/tasks?keyword=bad%0Akeyword&status=DELETED&input_type=%2Fetc%2Fpasswd' +
        '&creator=bad%0Acreator&tag=bad%0Atag&created_from=2026-07-30' +
        '&created_to=2026-07-01&cursor=bad%2Fcursor&page=01&page_size=100&extra=value',
    )

    expect(listTasks).toHaveBeenCalledTimes(1)
    expect(listTasks).toHaveBeenCalledWith({ page_size: 20 })
    expect(router.currentRoute.value.query).toEqual({
      page_size: '20',
    })
  })

  it('writes applied filters to the route and resets filters while retaining page size', async () => {
    const listTasks = vi.spyOn(api, 'listTasks').mockResolvedValue(page())
    const { router, wrapper } = await mountPanel(
      '/tasks?cursor=opaque_cursor-2&page_size=50',
    )
    listTasks.mockClear()

    wrapper.getComponent(FilterStub).vm.$emit('apply', {
      keyword: 'kernel',
      status: 'SCANNING',
      input_type: 'elf64',
      creator: 'Demo Operator',
      tag: 'firmware',
      created_from: '2026-07-01',
      created_to: '2026-07-30',
    })
    await flushPromises()

    expect(router.currentRoute.value.query).toEqual({
      keyword: 'kernel',
      status: 'SCANNING',
      input_type: 'elf64',
      creator: 'Demo Operator',
      tag: 'firmware',
      created_from: '2026-07-01',
      created_to: '2026-07-30',
      page_size: '50',
    })
    expect(listTasks).toHaveBeenLastCalledWith({
      keyword: 'kernel',
      status: 'SCANNING',
      input_type: 'elf64',
      creator: 'Demo Operator',
      tag: 'firmware',
      created_from: '2026-07-01',
      created_to: '2026-07-30',
      page_size: 50,
    })

    wrapper.getComponent(FilterStub).vm.$emit('reset')
    await flushPromises()

    expect(router.currentRoute.value.query).toEqual({
      page_size: '50',
    })
    expect(listTasks).toHaveBeenLastCalledWith({ page_size: 50 })
  })

  it('keeps the current table visible and announces a busy state while refiltering', async () => {
    const nextPage = pending<TaskPage>()
    vi.spyOn(api, 'listTasks')
      .mockResolvedValueOnce(page())
      .mockReturnValueOnce(nextPage.promise)

    const { wrapper } = await mountPanel('/tasks?page_size=20')
    expect(wrapper.findComponent(TableStub).exists()).toBe(true)

    wrapper.getComponent(FilterStub).vm.$emit('apply', {
      keyword: '',
      status: '',
      input_type: 'tar',
      creator: '',
      tag: '',
      created_from: '',
      created_to: '',
    })
    await flushPromises()

    expect(wrapper.findComponent(TableStub).exists()).toBe(true)
    expect(wrapper.get('.task-list__results').attributes('aria-busy')).toBe('true')
    expect(wrapper.text()).toContain('正在刷新任务列表')

    nextPage.resolve(page([task({ id: 'new', input_type: 'tar' })]))
    await flushPromises()
    expect(wrapper.get('.task-list__results').attributes('aria-busy')).toBe('false')
  })

  it('moves forward with server cursors and returns through local cursor history', async () => {
    const listTasks = vi.spyOn(api, 'listTasks')
      .mockResolvedValueOnce(page([task({ id: 'first' })], 'opaque_cursor-1'))
      .mockResolvedValueOnce(page([task({ id: 'second' })], 'opaque_cursor-2'))
      .mockResolvedValueOnce(page([task({ id: 'first-again' })], 'opaque_cursor-1'))

    const { router, wrapper } = await mountPanel('/tasks?page_size=20')
    const table = wrapper.getComponent(TableStub)
    expect(table.props()).toMatchObject({ hasNext: true, hasPrevious: false })

    table.vm.$emit('nextPage')
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({
      cursor: 'opaque_cursor-1',
      page_size: '20',
    })
    expect(listTasks).toHaveBeenLastCalledWith({
      cursor: 'opaque_cursor-1',
      page_size: 20,
    })
    expect(wrapper.getComponent(TableStub).props()).toMatchObject({
      canReset: true,
      hasPrevious: true,
      hasNext: true,
    })

    wrapper.getComponent(TableStub).vm.$emit('previousPage')
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ page_size: '20' })
    expect(listTasks).toHaveBeenLastCalledWith({ page_size: 20 })
  })

  it('keeps reset navigation available when a cursor page becomes empty', async () => {
    vi.spyOn(api, 'listTasks').mockResolvedValue(page([]))

    const { wrapper } = await mountPanel(
      '/tasks?cursor=opaque_cursor_deleted&page_size=20',
    )

    expect(wrapper.findComponent(StateStub).exists()).toBe(false)
    expect(wrapper.getComponent(TableStub).props()).toMatchObject({
      items: [],
      canReset: true,
    })
  })

  it('submits a confirmed task deletion from the list and refreshes the batch', async () => {
    const item = task()
    const listTasks = vi
      .spyOn(api, 'listTasks')
      .mockResolvedValueOnce(page([item]))
      .mockResolvedValueOnce(page([{ ...item, status: 'DELETING' }]))
    const deleteTask = vi.spyOn(api, 'deleteTask').mockResolvedValue({
      ...item,
      status: 'DELETING',
    })
    const { wrapper } = await mountPanel('/tasks?page_size=20', {
      userRole: 'administrator',
      currentUserId: 'admin-1',
    })

    wrapper.getComponent(TableStub).vm.$emit('delete', item)
    await wrapper.vm.$nextTick()
    expect(wrapper.get('[data-testid="delete-dialog"]').text()).toContain(
      item.name,
    )

    await wrapper.get('[data-testid="confirm-delete"]').trigger('click')
    await flushPromises()

    expect(deleteTask).toHaveBeenCalledWith(item.id)
    expect(listTasks).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).toContain('已进入删除流程')
  })
})
