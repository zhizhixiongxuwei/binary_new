import { describe, expect, it } from 'vitest'

import type { FileNodeDetail } from '@/api/types'
import {
  getFileNodeImageScanActionModel,
  isManualImageScanTarget,
} from '@/components/tasks/fileNodeImageScan'
import { resolveSampleRetention } from '@/utils/sampleRetention'

const NOW = new Date('2026-07-31T00:00:00.000Z')
const available = resolveSampleRetention({
  sampleExpiresAt: '2026-08-30T00:00:00.000Z',
  sampleDeletedAt: null,
  now: NOW,
})

function node(overrides: Partial<FileNodeDetail> = {}): FileNodeDetail {
  return {
    id: '42',
    parent_id: '41',
    logical_path: '/bundle/nested-image.tar',
    display_name: 'nested-image.tar',
    archive_name_id: '',
    node_type: 'file',
    depth: 10,
    format: 'docker-tar',
    mime_type: 'application/x-tar',
    architecture: 'linux/amd64',
    size_bytes: 4096,
    sha256: 'a'.repeat(64),
    extraction_status: 'limit_reached',
    error_code: 'max_auto_container_images',
    error_message: '自动镜像数量上限已达到',
    source_container: null,
    has_children: false,
    metadata_json: {},
    source_parent: null,
    ...overrides,
  }
}

describe('manual nested image scan action model', () => {
  it.each(['docker-tar', 'oci-tar'])(
    'enables a retained root %s image for an explicit Trivy run',
    (format) => {
      const model = getFileNodeImageScanActionModel({
        node: node({
          parent_id: null,
          depth: 0,
          format,
          extraction_status: 'indexed',
          error_code: '',
        }),
        taskStatus: 'SUCCEEDED',
        userRole: 'operator',
        mode: 'live',
        sampleRetention: available,
      })

      expect(model).toMatchObject({ visible: true, enabled: true })
      expect(model.reason).toContain('重新加入 Trivy')
    },
  )

  it.each(['docker-tar', 'oci-tar'])(
    'enables retained %s overflow nodes for write roles',
    (format) => {
      const model = getFileNodeImageScanActionModel({
        node: node({ format }),
        taskStatus: 'PARTIAL_SUCCEEDED',
        userRole: 'operator',
        mode: 'live',
        sampleRetention: available,
      })

      expect(model).toMatchObject({ visible: true, enabled: true })
      expect(model.reason).toContain('Trivy')
    },
  )

  it.each([
    node({ node_type: 'directory' }),
    node({ format: 'tar' }),
    node({ extraction_status: 'indexed' }),
    node({ error_code: 'archive_member_limit' }),
  ])('rejects non-image and non-eligible nested nodes', (value) => {
    expect(isManualImageScanTarget(value)).toBe(false)
  })

  it('shows that an active root image scan is already queued', () => {
    const model = getFileNodeImageScanActionModel({
      node: node({ parent_id: null, depth: 0, extraction_status: 'indexed' }),
      taskStatus: 'SCANNING',
      userRole: 'administrator',
      mode: 'live',
      sampleRetention: available,
    })

    expect(model).toMatchObject({ visible: true, enabled: false })
    expect(model.reason).toContain('已随上传任务排队')
  })

  it('hides the command from readers', () => {
    expect(
      getFileNodeImageScanActionModel({
        node: node(),
        taskStatus: 'FAILED',
        userRole: 'reader',
        mode: 'live',
        sampleRetention: available,
      }),
    ).toEqual({ visible: false, enabled: false, reason: '' })
  })

  it('keeps eligible nodes visible with precise disabled reasons', () => {
    const running = getFileNodeImageScanActionModel({
      node: node(),
      taskStatus: 'SCANNING',
      userRole: 'administrator',
      mode: 'live',
      sampleRetention: available,
    })
    const missingContent = getFileNodeImageScanActionModel({
      node: node({ sha256: '', size_bytes: null }),
      taskStatus: 'FAILED',
      userRole: 'administrator',
      mode: 'live',
      sampleRetention: available,
    })
    const preview = getFileNodeImageScanActionModel({
      node: node(),
      taskStatus: 'FAILED',
      userRole: 'administrator',
      mode: 'preview',
      sampleRetention: available,
    })

    expect(running).toMatchObject({ visible: true, enabled: false })
    expect(running.reason).toContain('任务结束后')
    expect(missingContent.reason).toContain('完整镜像内容')
    expect(preview.reason).toContain('界面预览')
  })

  it('explains expired and deleted retained content', () => {
    for (const [sampleDeletedAt, reason] of [
      [null, '样本保留期已到'],
      ['cleanup-marker', '任务原始样本已清理'],
    ] as const) {
      const model = getFileNodeImageScanActionModel({
        node: node(),
        taskStatus: 'FAILED',
        userRole: 'operator',
        mode: 'live',
        sampleRetention: resolveSampleRetention({
          sampleExpiresAt: NOW.toISOString(),
          sampleDeletedAt,
          now: NOW,
        }),
      })
      expect(model).toMatchObject({ visible: true, enabled: false })
      expect(model.reason).toContain(reason)
    }
  })
})
