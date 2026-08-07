import { hasUnsafeDisplayCharacter } from '@/components/tasks/results/displayText'

const MAX_METHODS_TO_PARSE = 3_000
const MAX_KEY_LENGTH = 1_000
const MAX_NAME_LENGTH = 1_024
const MAX_TEXT_LENGTH = 4_096
const METHOD_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/@+\-$]{0,999}$/

export interface BytecodeMethodRange {
  offsetBytes: number
  sizeBytes: number
}

export interface BytecodeSourceRange {
  startLine: number
  endLine: number
}

export interface BytecodeMethodIndexEntry {
  key: string
  name: string
  qualifiedName: string
  descriptor: string
  signature: string
  source?: BytecodeSourceRange
  bytecode?: BytecodeMethodRange
}

export interface ParsedBytecodeMethodIndex {
  present: boolean
  declaredCount: number
  invalidCount: number
  omittedCount: number
  methods: readonly BytecodeMethodIndexEntry[]
}

function isRecord(
  value: unknown,
): value is Readonly<Record<string, unknown>> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

function boundedString(
  value: unknown,
  maxLength: number,
  required = false,
): string | undefined {
  if (value === undefined && !required) return ''
  if (typeof value !== 'string') return undefined
  if (
    (required && !value.trim()) ||
    value.length > maxLength ||
    hasUnsafeDisplayCharacter(value)
  ) {
    return undefined
  }
  return value
}

function safeUnsignedInteger(value: unknown): number | undefined {
  return typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    !Object.is(value, -0) &&
    value >= 0
    ? value
    : undefined
}

function parseBytecodeRange(
  value: unknown,
): BytecodeMethodRange | undefined | false {
  if (value === undefined) return undefined
  if (!isRecord(value)) return false
  const offsetBytes = safeUnsignedInteger(value.offset_bytes)
  const sizeBytes = safeUnsignedInteger(value.size_bytes)
  if (
    offsetBytes === undefined ||
    sizeBytes === undefined ||
    sizeBytes === 0 ||
    !Number.isSafeInteger(offsetBytes + sizeBytes)
  ) {
    return false
  }
  return { offsetBytes, sizeBytes }
}

function parseSourceRange(
  value: unknown,
): BytecodeSourceRange | undefined | false {
  if (value === undefined) return undefined
  if (!isRecord(value)) return false
  const startLine = safeUnsignedInteger(value.start_line)
  const endLine = safeUnsignedInteger(value.end_line)
  if (
    startLine === undefined ||
    endLine === undefined ||
    startLine === 0 ||
    endLine < startLine
  ) {
    return false
  }
  return { startLine, endLine }
}

function parseMethod(
  value: unknown,
): BytecodeMethodIndexEntry | undefined {
  if (!isRecord(value)) return undefined
  const key = boundedString(value.key, MAX_KEY_LENGTH, true)
  const name = boundedString(value.name, MAX_NAME_LENGTH, true)
  const qualifiedName = boundedString(value.qualified_name, MAX_TEXT_LENGTH)
  const descriptor = boundedString(value.descriptor, MAX_TEXT_LENGTH)
  const signature = boundedString(value.signature, MAX_TEXT_LENGTH)
  const source = parseSourceRange(value.source)
  const bytecode = parseBytecodeRange(value.bytecode)
  if (
    key === undefined ||
    !METHOD_KEY_PATTERN.test(key) ||
    name === undefined ||
    qualifiedName === undefined ||
    descriptor === undefined ||
    signature === undefined ||
    source === false ||
    bytecode === false
  ) {
    return undefined
  }
  return {
    key,
    name,
    qualifiedName,
    descriptor,
    signature,
    ...(source ? { source } : {}),
    ...(bytecode ? { bytecode } : {}),
  }
}

function parseIndex(
  diagnostics: unknown,
): ParsedBytecodeMethodIndex {
  if (
    !isRecord(diagnostics) ||
    !Object.prototype.hasOwnProperty.call(diagnostics, 'methods')
  ) {
    return {
      present: false,
      declaredCount: 0,
      invalidCount: 0,
      omittedCount: 0,
      methods: [],
    }
  }
  const rawMethods = diagnostics.methods
  if (!Array.isArray(rawMethods)) {
    return {
      present: true,
      declaredCount: 0,
      invalidCount: 1,
      omittedCount: 0,
      methods: [],
    }
  }

  const methods: BytecodeMethodIndexEntry[] = []
  const methodKeys = new Set<string>()
  let invalidCount = 0
  const parseCount = Math.min(rawMethods.length, MAX_METHODS_TO_PARSE)
  for (let index = 0; index < parseCount; index += 1) {
    const method = parseMethod(rawMethods[index])
    if (!method || methodKeys.has(method.key)) {
      invalidCount += 1
      continue
    }
    methodKeys.add(method.key)
    methods.push(method)
  }

  return {
    present: true,
    declaredCount: rawMethods.length,
    invalidCount,
    omittedCount: Math.max(0, rawMethods.length - parseCount),
    methods,
  }
}

export function parseBytecodeMethodIndex(
  diagnostics: unknown,
): ParsedBytecodeMethodIndex {
  try {
    return parseIndex(diagnostics)
  } catch {
    return {
      present: false,
      declaredCount: 0,
      invalidCount: 0,
      omittedCount: 0,
      methods: [],
    }
  }
}
