import { describe, expect, it } from 'vitest'

import {
  FileNodeContractError,
  parseFileNodeDetail,
  parseFileNodePage,
} from '@/api/fileNodeContract'

function node() {
  return {
    id: '18446744073709551614',
    parent_id: '18446744073709551613',
    logical_path: '/outer.tar/nested.img/bin/app',
    display_name: 'app',
    archive_name_id: 'b64:YmluL2FwcA==',
    node_type: 'file',
    depth: 3,
    format: 'elf64',
    mime_type: 'application/x-elf',
    architecture: 'x86_64',
    size_bytes: 8192,
    sha256: 'a'.repeat(64),
    extraction_status: 'indexed',
    error_code: '',
    error_message: '',
    source_container: {
      id: '18446744073709551612',
      logical_path: '/outer.tar/nested.img',
      format: 'ext4',
    },
    has_children: false,
  }
}

describe('file-node runtime contract', () => {
  it('preserves exact decimal IDs and a strict source-container relation', () => {
    const page = parseFileNodePage({
      items: [node()],
      next_cursor: '18446744073709551614',
    })

    expect(page.items[0]?.source_container).toEqual({
      id: '18446744073709551612',
      logical_path: '/outer.tar/nested.img',
      format: 'ext4',
    })
    expect(page.next_cursor).toBe('18446744073709551614')
  })

  it('accepts a root detail with an explicit null source container', () => {
    const root = {
      ...node(),
      id: '1',
      parent_id: null,
      logical_path: '/root.tar',
      display_name: 'root.tar',
      archive_name_id: '',
      depth: 0,
      source_container: null,
      metadata_json: {},
      source_parent: null,
    }

    expect(parseFileNodeDetail(root)).toMatchObject({
      id: '1',
      source_container: null,
      source_parent: null,
    })
  })

  it.each([
    ['missing relation', { ...node(), source_container: undefined }],
    [
      'unknown relation property',
      {
        ...node(),
        source_container: {
          ...node().source_container,
          repository_path: '/private/repository',
        },
      },
    ],
    [
      'invalid relation identifier',
      {
        ...node(),
        source_container: { ...node().source_container, id: '01' },
      },
    ],
  ])('rejects %s', (_label, invalid) => {
    expect(() => parseFileNodePage({ items: [invalid] })).toThrow(
      FileNodeContractError,
    )
  })
})
