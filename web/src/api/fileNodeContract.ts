import type {
  FileNode,
  FileNodeDetail,
  FileNodePage,
  FileNodeSourceContainer,
  FileNodeSourceParent,
  FileNodeType,
  JsonValue,
} from '@/api/types'

const decimalId = /^[1-9][0-9]{0,19}$/
const sha256 = /^[0-9a-f]{64}$/
const archiveNameId =
  /^(?:|b64:[A-Za-z0-9+/]*={0,2}|sha256:[0-9a-f]{64})$/
const nodeTypes = new Set<FileNodeType>([
  'file',
  'directory',
  'symlink',
  'hardlink',
  'special',
])
const extractionStatuses = new Set([
  'indexed',
  'extracted',
  'skipped',
  'unsupported',
  'limit_reached',
  'failed',
])
const nodeKeys = [
  'id',
  'parent_id',
  'logical_path',
  'display_name',
  'archive_name_id',
  'node_type',
  'depth',
  'format',
  'mime_type',
  'architecture',
  'size_bytes',
  'sha256',
  'extraction_status',
  'error_code',
  'error_message',
  'source_container',
  'has_children',
] as const

export class FileNodeContractError extends Error {
  constructor(field: string) {
    super(`文件节点响应不符合接口契约：${field}`)
    this.name = 'FileNodeContractError'
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new FileNodeContractError(field)
  }
  return value as Record<string, unknown>
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
  field: string,
): void {
  const allowed = new Set([...required, ...optional])
  if (
    required.some((key) => !Object.prototype.hasOwnProperty.call(value, key)) ||
    Object.keys(value).some((key) => !allowed.has(key))
  ) {
    throw new FileNodeContractError(field)
  }
}

function stringValue(
  value: unknown,
  field: string,
  minLength: number,
  maxLength: number,
): string {
  if (
    typeof value !== 'string' ||
    value.length < minLength ||
    value.length > maxLength
  ) {
    throw new FileNodeContractError(field)
  }
  return value
}

function idValue(value: unknown, field: string): string {
  const id = stringValue(value, field, 1, 20)
  if (!decimalId.test(id)) throw new FileNodeContractError(field)
  return id
}

function nullableId(value: unknown, field: string): string | null {
  return value === null ? null : idValue(value, field)
}

function sourceContainerValue(
  value: unknown,
  field: string,
): FileNodeSourceContainer | null {
  if (value === null) return null
  const source = record(value, field)
  exactKeys(source, ['id', 'logical_path', 'format'], [], field)
  return {
    id: idValue(source.id, `${field}.id`),
    logical_path: stringValue(
      source.logical_path,
      `${field}.logical_path`,
      1,
      2_048,
    ),
    format: stringValue(source.format, `${field}.format`, 1, 64),
  }
}

function sourceParentValue(
  value: unknown,
  field: string,
): FileNodeSourceParent | null {
  if (value === null) return null
  const source = record(value, field)
  exactKeys(source, ['id', 'logical_path'], [], field)
  return {
    id: idValue(source.id, `${field}.id`),
    logical_path: stringValue(
      source.logical_path,
      `${field}.logical_path`,
      1,
      2_048,
    ),
  }
}

function nodeValue(value: unknown, field: string): FileNode {
  const node = record(value, field)
  exactKeys(node, nodeKeys, [], field)
  const nodeType = stringValue(node.node_type, `${field}.node_type`, 1, 16)
  const extractionStatus = stringValue(
    node.extraction_status,
    `${field}.extraction_status`,
    1,
    32,
  )
  if (!nodeTypes.has(nodeType as FileNodeType)) {
    throw new FileNodeContractError(`${field}.node_type`)
  }
  if (!extractionStatuses.has(extractionStatus)) {
    throw new FileNodeContractError(`${field}.extraction_status`)
  }
  if (
    !Number.isInteger(node.depth) ||
    (node.depth as number) < 0 ||
    (node.depth as number) > 10
  ) {
    throw new FileNodeContractError(`${field}.depth`)
  }
  if (
    node.size_bytes !== null &&
    (!Number.isSafeInteger(node.size_bytes) ||
      (node.size_bytes as number) < 0 ||
      (node.size_bytes as number) > 53_687_091_200)
  ) {
    throw new FileNodeContractError(`${field}.size_bytes`)
  }
  const archiveId = stringValue(
    node.archive_name_id,
    `${field}.archive_name_id`,
    0,
    2_736,
  )
  if (!archiveNameId.test(archiveId)) {
    throw new FileNodeContractError(`${field}.archive_name_id`)
  }
  const digest = stringValue(node.sha256, `${field}.sha256`, 0, 64)
  if (digest !== '' && !sha256.test(digest)) {
    throw new FileNodeContractError(`${field}.sha256`)
  }
  if (typeof node.has_children !== 'boolean') {
    throw new FileNodeContractError(`${field}.has_children`)
  }

  return {
    id: idValue(node.id, `${field}.id`),
    parent_id: nullableId(node.parent_id, `${field}.parent_id`),
    logical_path: stringValue(
      node.logical_path,
      `${field}.logical_path`,
      1,
      2_048,
    ),
    display_name: stringValue(
      node.display_name,
      `${field}.display_name`,
      1,
      512,
    ),
    archive_name_id: archiveId,
    node_type: nodeType as FileNodeType,
    depth: node.depth as number,
    format: stringValue(node.format, `${field}.format`, 0, 64),
    mime_type: stringValue(node.mime_type, `${field}.mime_type`, 0, 255),
    architecture: stringValue(
      node.architecture,
      `${field}.architecture`,
      0,
      64,
    ),
    size_bytes: node.size_bytes as number | null,
    sha256: digest,
    extraction_status: extractionStatus,
    error_code: stringValue(node.error_code, `${field}.error_code`, 0, 128),
    error_message: stringValue(
      node.error_message,
      `${field}.error_message`,
      0,
      2_048,
    ),
    source_container: sourceContainerValue(
      node.source_container,
      `${field}.source_container`,
    ),
    has_children: node.has_children,
  }
}

function metadataValue(value: unknown, field: string): JsonValue {
  if (value === null) return null
  return record(value, field) as JsonValue
}

export function parseFileNodePage(value: unknown): FileNodePage {
  const page = record(value, 'data')
  exactKeys(page, ['items'], ['next_cursor'], 'data')
  if (!Array.isArray(page.items) || page.items.length > 200) {
    throw new FileNodeContractError('data.items')
  }
  const parsed: FileNodePage = {
    items: page.items.map((item, index) =>
      nodeValue(item, `data.items[${index}]`),
    ),
  }
  if (page.next_cursor !== undefined) {
    parsed.next_cursor = idValue(page.next_cursor, 'data.next_cursor')
  }
  return parsed
}

export function parseFileNodeDetail(value: unknown): FileNodeDetail {
  const detail = record(value, 'data')
  exactKeys(detail, [...nodeKeys, 'metadata_json', 'source_parent'], [], 'data')
  return {
    ...nodeValue(
      Object.fromEntries(nodeKeys.map((key) => [key, detail[key]])),
      'data',
    ),
    metadata_json: metadataValue(detail.metadata_json, 'data.metadata_json'),
    source_parent: sourceParentValue(detail.source_parent, 'data.source_parent'),
  }
}
