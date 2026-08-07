import { describe, expect, it } from 'vitest'

import type { FileNodeDetail } from '@/api/types'
import {
  getFileNodeDecompileActionModel,
} from '@/components/tasks/fileNodeDecompile'
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
    parent_id: null,
    logical_path: '/app.exe',
    display_name: 'app.exe',
    archive_name_id: '',
    node_type: 'file',
    depth: 0,
    format: 'pe32+',
    mime_type: 'application/octet-stream',
    architecture: 'x86_64',
    size_bytes: 4096,
    sha256: 'a'.repeat(64),
    extraction_status: 'indexed',
    error_code: '',
    error_message: '',
    source_container: null,
    has_children: false,
    metadata_json: {},
    source_parent: null,
    ...overrides,
  }
}

describe('file node decompile action model', () => {
  it('enables supported retained files for write roles after task completion', () => {
    const model = getFileNodeDecompileActionModel({
      node: node(),
      taskStatus: 'FAILED',
      userRole: 'operator',
      mode: 'live',
      sampleRetention: available,
    })

    expect(model).toMatchObject({ visible: true, enabled: true })
    expect(model.reason).toContain('处理队列')
  })

  it('enables the verified thin Mach-O x86_64 path', () => {
    const model = getFileNodeDecompileActionModel({
      node: node({
        logical_path: '/gocloc',
        display_name: 'gocloc',
        format: 'macho-thin',
        architecture: 'x86_64',
      }),
      taskStatus: 'SUCCEEDED',
      userRole: 'administrator',
      mode: 'live',
      sampleRetention: available,
    })

    expect(model).toMatchObject({ visible: true, enabled: true })
  })

  it.each([
    { userRole: 'reader' as const, value: node() },
    { userRole: 'operator' as const, value: node({ node_type: 'directory' }) },
    { userRole: 'administrator' as const, value: node({ format: 'zip' }) },
    {
      userRole: 'administrator' as const,
      value: node({ format: 'macho-thin', architecture: 'aarch64' }),
    },
    {
      userRole: 'administrator' as const,
      value: node({ format: 'macho-fat', architecture: 'universal' }),
    },
  ])('hides reader, non-file, and unsupported targets', ({ userRole, value }) => {
    expect(
      getFileNodeDecompileActionModel({
        node: value,
        taskStatus: 'FAILED',
        userRole,
        mode: 'live',
        sampleRetention: available,
      }),
    ).toMatchObject({ visible: false, enabled: false })
  })

  it('keeps supported commands visible with a precise disabled reason', () => {
    const running = getFileNodeDecompileActionModel({
      node: node(),
      taskStatus: 'SCANNING',
      userRole: 'administrator',
      mode: 'live',
      sampleRetention: available,
    })
    const noSource = getFileNodeDecompileActionModel({
      node: node({ extraction_status: 'failed' }),
      taskStatus: 'FAILED',
      userRole: 'administrator',
      mode: 'live',
      sampleRetention: available,
    })
    const preview = getFileNodeDecompileActionModel({
      node: node(),
      taskStatus: 'FAILED',
      userRole: 'administrator',
      mode: 'preview',
      sampleRetention: available,
    })

    expect(running).toMatchObject({ visible: true, enabled: false })
    expect(running.reason).toContain('任务结束后')
    expect(noSource.reason).toContain('已保留内容')
    expect(preview.reason).toContain('界面预览')
  })

  it.each([
    {
      sampleExpiresAt: NOW.toISOString(),
      sampleDeletedAt: null,
      reason: '样本保留期已到',
    },
    {
      sampleExpiresAt: '2026-08-30T00:00:00.000Z',
      sampleDeletedAt: 'server-cleanup-marker',
      reason: '任务原始样本已清理',
    },
  ])(
    'uses the shared retention reason for unavailable samples',
    ({ sampleExpiresAt, sampleDeletedAt, reason }) => {
      const model = getFileNodeDecompileActionModel({
        node: node(),
        taskStatus: 'FAILED',
        userRole: 'operator',
        mode: 'live',
        sampleRetention: resolveSampleRetention({
          sampleExpiresAt,
          sampleDeletedAt,
          now: NOW,
        }),
      })

      expect(model).toMatchObject({ visible: true, enabled: false })
      expect(model.reason).toContain(reason)
    },
  )
})
