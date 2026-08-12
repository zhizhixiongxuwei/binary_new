import { flushPromises, mount } from '@vue/test-utils'
import { ElMessageBox } from 'element-plus'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/api/client'
import type { ArchiveImport } from '@/api/types'
import ArchiveImportWorkspace from '@/components/uploads/ArchiveImportWorkspace.vue'

function importValue(): ArchiveImport {
  return {
    id: 'import-1',
    upload_id: 'upload-1',
    filename: 'bundle.zip',
    status: 'ready',
    scanned_entries: 8,
    total_entries: 8,
    eligible_entries: 5,
    skipped_entries: 3,
    created_tasks: 2,
    created_at: '2026-08-11T08:00:00Z',
    updated_at: '2026-08-11T08:01:00Z',
  }
}

describe('ArchiveImportWorkspace', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('requires an impact-aware confirmation before deleting the outer upload', async () => {
    vi.spyOn(api, 'getArchiveImport').mockResolvedValue(importValue())
    vi.spyOn(api, 'listArchiveImportEntries').mockResolvedValue({ items: [] })
    const deleteUpload = vi.spyOn(api, 'deleteUpload').mockResolvedValue()
    const confirm = vi
      .spyOn(ElMessageBox, 'confirm')
      .mockRejectedValueOnce(new Error('cancelled'))
      .mockResolvedValueOnce('confirm' as never)
    const wrapper = mount(ArchiveImportWorkspace, {
      props: {
        importId: 'import-1',
        uploadId: 'upload-1',
        filename: 'bundle.zip',
      },
      global: {
        stubs: {
          ArchiveImportEntryTable: true,
          ArchiveImportBatchActions: true,
          ElProgress: true,
          ElSelect: true,
          ElOption: true,
        },
      },
    })
    await flushPromises()
    const deleteButton = wrapper.get('button[aria-label="删除归档上传"]')

    await deleteButton.trigger('click')
    await flushPromises()
    expect(deleteUpload).not.toHaveBeenCalled()

    await deleteButton.trigger('click')
    await flushPromises()

    expect(confirm).toHaveBeenCalledWith(
      expect.stringContaining('3 个尚未创建任务的候选'),
      '删除外层归档上传？',
      expect.objectContaining({
        confirmButtonText: '删除归档上传',
        cancelButtonText: '保留归档',
        type: 'warning',
      }),
    )
    expect(confirm.mock.calls[1]?.[0]).toContain('已创建的 2 个任务及其样本会保留')
    expect(deleteUpload).toHaveBeenCalledWith('upload-1')
    expect(wrapper.emitted('deleted')).toHaveLength(1)
    wrapper.unmount()
  })
})
