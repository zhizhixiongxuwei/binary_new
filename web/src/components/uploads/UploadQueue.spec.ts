import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import UploadQueue from '@/components/uploads/UploadQueue.vue'
import type { UploadQueueItem } from '@/composables/useChunkUpload'

describe('UploadQueue', () => {
  it('emits the task id from a completed queue row', async () => {
    const item: UploadQueueItem = {
      localId: 'local-1',
      file: new File(['binary'], 'sample.bin'),
      status: 'completed',
      progress: 100,
      uploadedBytes: 6,
      errorMessage: '',
      uploadId: 'upload-1',
      partSize: 32 * 1024 * 1024,
      taskId: 'task-1',
      taskIdempotencyKey: 'idempotency-1',
      canRetry: false,
    }
    const wrapper = mount(UploadQueue, {
      props: {
        items: [item],
        activeId: null,
      },
      global: {
        stubs: {
          ElProgress: true,
        },
      },
    })

    const openTask = wrapper.get('button[aria-label="查看任务"]')
    expect(openTask.text()).toBe('查看任务')
    await openTask.trigger('click')

    expect(wrapper.emitted('openTask')).toEqual([['task-1']])
  })

  it('does not offer retry for a terminal upload failure', () => {
    const item: UploadQueueItem = {
      localId: 'local-2',
      file: new File(['binary'], 'conflict.bin'),
      status: 'failed',
      progress: 0,
      uploadedBytes: 0,
      errorMessage: '分片内容冲突，请移除后重新选择文件',
      uploadId: 'upload-2',
      partSize: 32 * 1024 * 1024,
      taskIdempotencyKey: 'idempotency-2',
      canRetry: false,
    }
    const wrapper = mount(UploadQueue, {
      props: {
        items: [item],
        activeId: null,
      },
      global: {
        stubs: {
          ElProgress: true,
        },
      },
    })

    expect(wrapper.find('button[aria-label="重试上传"]').exists()).toBe(false)
    expect(wrapper.get('button[aria-label="移除文件"]').attributes('aria-label')).toBe('移除文件')
  })

  it('keeps long filenames and failure details available to narrow layouts', () => {
    const fileName =
      'this-is-a-very-long-offline-container-image-file-name-without-breaks.tar'
    const errorMessage =
      '分片内容冲突：this-is-a-very-long-error-token-without-natural-break-points'
    const item: UploadQueueItem = {
      localId: 'local-3',
      file: new File(['binary'], fileName),
      status: 'failed',
      progress: 64,
      uploadedBytes: 6,
      errorMessage,
      uploadId: 'upload-3',
      partSize: 32 * 1024 * 1024,
      taskIdempotencyKey: 'idempotency-3',
      canRetry: true,
    }
    const wrapper = mount(UploadQueue, {
      props: {
        items: [item],
        activeId: null,
      },
      global: {
        stubs: {
          ElProgress: true,
        },
      },
    })

    expect(wrapper.get('[role="list"]').attributes('aria-label')).toBe('上传队列')
    expect(wrapper.get('[role="listitem"]').attributes('role')).toBe('listitem')
    expect(wrapper.get('.upload-row__heading strong').attributes('title')).toBe(fileName)
    expect(wrapper.get('.upload-row__heading strong').text()).toBe(fileName)
    expect(wrapper.get('.upload-row__error').text()).toBe(errorMessage)
    expect(wrapper.get('.upload-row__state').attributes('aria-live')).toBe('polite')
    expect(wrapper.get('el-progress-stub').attributes('aria-label')).toBe(
      `${fileName} 上传进度 64%`,
    )
  })

  it('hides command glyphs from assistive technology while retaining button names', () => {
    const item: UploadQueueItem = {
      localId: 'local-4',
      file: new File(['binary'], 'paused.img'),
      status: 'paused',
      progress: 32,
      uploadedBytes: 6,
      errorMessage: '',
      uploadId: 'upload-4',
      partSize: 32 * 1024 * 1024,
      taskIdempotencyKey: 'idempotency-4',
      canRetry: true,
    }
    const wrapper = mount(UploadQueue, {
      props: {
        items: [item],
        activeId: null,
      },
      global: {
        stubs: {
          ElProgress: true,
        },
      },
    })

    expect(wrapper.get('button[aria-label="继续上传"]').attributes('title')).toBe('继续上传')
    expect(wrapper.get('button[aria-label="移除文件"]').attributes('title')).toBe('移除文件')
    for (const icon of wrapper.findAll('.upload-row__commands svg')) {
      expect(icon.attributes('aria-hidden')).toBe('true')
    }
  })

  it('locks the remove command while server-side cancellation is pending', () => {
    const item: UploadQueueItem = {
      localId: 'local-5',
      file: new File(['binary'], 'pending-remove.tar'),
      status: 'paused',
      progress: 32,
      uploadedBytes: 6,
      errorMessage: '',
      uploadId: 'upload-5',
      partSize: 32 * 1024 * 1024,
      taskIdempotencyKey: 'idempotency-5',
      canRetry: true,
      serverStatus: 'uploading',
      removing: true,
    }
    const wrapper = mount(UploadQueue, {
      props: {
        items: [item],
        activeId: null,
      },
      global: {
        stubs: {
          ElProgress: true,
        },
      },
    })

    const button = wrapper.get('button[aria-label="正在移除文件"]')
    expect(button.attributes('disabled')).toBeDefined()
    expect(button.attributes('aria-busy')).toBe('true')
    expect(button.find('.upload-row__spinner').exists()).toBe(true)
  })
})
