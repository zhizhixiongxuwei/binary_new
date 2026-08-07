import type { LocationQuery, LocationQueryRaw } from 'vue-router'

import type { TaskStatus } from '@/api/types'

export const TASK_PAGE_SIZES = [10, 20, 50] as const

export const USER_TASK_STATUS_OPTIONS = [
  { value: 'UPLOADING', label: '上传中' },
  { value: 'QUEUED', label: '排队中' },
  { value: 'VALIDATING', label: '校验中' },
  { value: 'IDENTIFYING', label: '识别中' },
  { value: 'EXTRACTING', label: '解包中' },
  { value: 'INDEXING', label: '索引中' },
  { value: 'SCANNING', label: '检测中' },
  { value: 'REPORTING', label: '报告生成中' },
  { value: 'SUCCEEDED', label: '已完成' },
  { value: 'PARTIAL_SUCCEEDED', label: '部分完成' },
  { value: 'FAILED', label: '失败' },
  { value: 'CANCEL_REQUESTED', label: '正在取消' },
  { value: 'CANCELLED', label: '已取消' },
  { value: 'DELETING', label: '正在删除' },
] as const satisfies readonly { value: TaskStatus; label: string }[]

export type TaskFilterStatus = (typeof USER_TASK_STATUS_OPTIONS)[number]['value']

export interface InputFormatGroup {
  label: string
  options: readonly string[]
}

export const INPUT_FORMAT_GROUPS: readonly InputFormatGroup[] = [
  {
    label: '二进制',
    options: ['pe32', 'pe32+', 'elf32', 'elf64', 'macho-thin', 'macho-fat'],
  },
  {
    label: '字节码',
    options: ['java-class', 'dex', 'pyc'],
  },
  {
    label: '归档',
    options: [
      'zip',
      'tar',
      'gzip',
      'bzip2',
      'xz',
      'zstd',
      '7z',
      'rar',
      'cab',
      'cpio',
      'ar',
      'rpm',
      'deb',
      'jar',
      'war',
      'ear',
      'apk',
    ],
  },
  {
    label: '映像',
    options: ['ext2', 'ext3', 'ext4', 'squashfs', 'iso9660', 'udf', 'mbr-img', 'gpt-img'],
  },
  {
    label: '容器',
    options: ['docker-tar', 'oci-tar'],
  },
  {
    label: '其他',
    options: ['unknown'],
  },
] as const

export interface TaskFilterValue {
  keyword: string
  status: TaskFilterStatus | ''
  input_type: string
  creator: string
  tag: string
  created_from: string
  created_to: string
}

export interface TaskListRouteState extends TaskFilterValue {
  cursor: string
  page_size: (typeof TASK_PAGE_SIZES)[number]
}

export const DEFAULT_TASK_LIST_STATE: Readonly<TaskListRouteState> = {
  keyword: '',
  status: '',
  input_type: '',
  creator: '',
  tag: '',
  created_from: '',
  created_to: '',
  cursor: '',
  page_size: 20,
}

const userTaskStatuses = new Set<string>(
  USER_TASK_STATUS_OPTIONS.map((option) => option.value),
)
const inputFormatPattern = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/
const isoDatePattern = /^(\d{4})-(\d{2})-(\d{2})$/
const opaqueCursorPattern = /^[A-Za-z0-9_-]{1,256}$/

type RouteQueryValue = LocationQuery[string] | undefined

function singleQueryValue(value: RouteQueryValue): string | undefined {
  return typeof value === 'string' ? value : undefined
}

function parsePageSize(value: RouteQueryValue): TaskListRouteState['page_size'] {
  const candidate = singleQueryValue(value)
  if (!candidate || !/^[1-9]\d*$/.test(candidate)) {
    return DEFAULT_TASK_LIST_STATE.page_size
  }
  const numericValue = Number(candidate)
  return TASK_PAGE_SIZES.includes(numericValue as TaskListRouteState['page_size'])
    ? (numericValue as TaskListRouteState['page_size'])
    : DEFAULT_TASK_LIST_STATE.page_size
}

function parseCursor(value: RouteQueryValue): string {
  const candidate = singleQueryValue(value)
  return candidate && opaqueCursorPattern.test(candidate) ? candidate : ''
}

function hasControlCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0
    return codePoint <= 0x1f || codePoint === 0x7f
  })
}

function normalizeText(
  value: string,
  maximumLength: number,
): string | null {
  const candidate = value.trim()
  if (
    hasControlCharacter(candidate) ||
    Array.from(candidate).length > maximumLength
  ) {
    return null
  }
  return candidate
}

export function normalizeTaskKeyword(value: string): string | null {
  return normalizeText(value, 255)
}

export function normalizeTaskCreator(value: string): string | null {
  return normalizeText(value, 128)
}

export function normalizeTaskTag(value: string): string | null {
  return normalizeText(value, 64)
}

function parseText(
  value: RouteQueryValue,
  normalize: (candidate: string) => string | null,
): string {
  const candidate = singleQueryValue(value)
  if (candidate === undefined) return ''
  return normalize(candidate) ?? ''
}

function parseStatus(value: RouteQueryValue): TaskFilterStatus | '' {
  const candidate = singleQueryValue(value)
  return candidate && userTaskStatuses.has(candidate)
    ? (candidate as TaskFilterStatus)
    : ''
}

export function normalizeInputFormat(value: string): string | null {
  const candidate = value.trim().toLowerCase()
  if (!candidate) return ''
  return inputFormatPattern.test(candidate) ? candidate : null
}

function parseInputFormat(value: RouteQueryValue): string {
  const candidate = singleQueryValue(value)
  if (candidate === undefined) return ''
  return normalizeInputFormat(candidate) ?? ''
}

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
}

export function normalizeTaskDate(value: string): string | null {
  const candidate = value.trim()
  if (!candidate) return ''
  const match = isoDatePattern.exec(candidate)
  if (!match) return null

  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  if (year < 1 || month < 1 || month > 12 || day < 1) return null

  const daysInMonth = [
    31,
    isLeapYear(year) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ]
  return day <= (daysInMonth[month - 1] ?? 0) ? candidate : null
}

function parseTaskDate(value: RouteQueryValue): string {
  const candidate = singleQueryValue(value)
  if (candidate === undefined) return ''
  return normalizeTaskDate(candidate) ?? ''
}

export function taskDateRangeIsValid(
  createdFrom: string,
  createdTo: string,
): boolean {
  return !createdFrom || !createdTo || createdFrom <= createdTo
}

export function parseTaskListRouteQuery(query: LocationQuery): TaskListRouteState {
  const pageSize = parsePageSize(query.page_size)
  let createdFrom = parseTaskDate(query.created_from)
  let createdTo = parseTaskDate(query.created_to)
  if (!taskDateRangeIsValid(createdFrom, createdTo)) {
    createdFrom = ''
    createdTo = ''
  }
  return {
    keyword: parseText(query.keyword, normalizeTaskKeyword),
    status: parseStatus(query.status),
    input_type: parseInputFormat(query.input_type),
    creator: parseText(query.creator, normalizeTaskCreator),
    tag: parseText(query.tag, normalizeTaskTag),
    created_from: createdFrom,
    created_to: createdTo,
    cursor: parseCursor(query.cursor),
    page_size: pageSize,
  }
}

export function serializeTaskListRouteQuery(
  state: TaskListRouteState,
): LocationQueryRaw {
  const query: LocationQueryRaw = {
    page_size: String(state.page_size),
  }
  if (state.cursor) query.cursor = state.cursor
  if (state.keyword) query.keyword = state.keyword
  if (state.status) query.status = state.status
  if (state.input_type) query.input_type = state.input_type
  if (state.creator) query.creator = state.creator
  if (state.tag) query.tag = state.tag
  if (state.created_from) query.created_from = state.created_from
  if (state.created_to) query.created_to = state.created_to
  return query
}

export function taskRouteQueryIsCanonical(
  current: LocationQuery,
  canonical: LocationQueryRaw,
): boolean {
  const currentKeys = Object.keys(current).sort()
  const canonicalKeys = Object.keys(canonical).sort()
  if (
    currentKeys.length !== canonicalKeys.length ||
    currentKeys.some((key, index) => key !== canonicalKeys[index])
  ) {
    return false
  }
  return canonicalKeys.every((key) => {
    const currentValue = current[key]
    const canonicalValue = canonical[key]
    return typeof currentValue === 'string' && currentValue === canonicalValue
  })
}
