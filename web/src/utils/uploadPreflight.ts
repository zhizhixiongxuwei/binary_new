import type { InputCategory } from '@/api/types'

const HEAD_LIMIT = 4_096
const TAIL_LIMIT = 65_557

export const inputCategoryLabels: Record<InputCategory, string> = {
  binary: '01 二进制格式',
  archive: '02 压缩包格式',
  container: '03 容器镜像格式',
}

export const inputCategoryAccept: Record<InputCategory, string> = {
  binary:
    '.exe,.dll,.sys,.elf,.so,.dylib,.class,.jar,.war,.ear,.dex,.apk,.pyc,application/octet-stream,application/java-archive,application/vnd.android.package-archive',
  archive:
    '.zip,.7z,.rar,.tar,.tgz,.gz,.bz2,.xz,.zst,.cab,.cpio,.ar,.deb,.rpm,application/zip,application/x-7z-compressed,application/x-rar-compressed,application/x-tar,application/gzip',
  container: '.tar,application/x-tar,application/octet-stream',
}

interface MagicMatch {
  format: string
  allowedCategories: readonly InputCategory[]
}

export interface UploadPreflightResult {
  accepted: boolean
  detectedFormat?: string
  message?: string
}

function startsWith(bytes: Uint8Array, signature: readonly number[]): boolean {
  return (
    bytes.length >= signature.length &&
    signature.every((value, index) => bytes[index] === value)
  )
}

function asciiAt(bytes: Uint8Array, offset: number, value: string): boolean {
  if (bytes.length < offset + value.length) return false
  return Array.from(value).every(
    (character, index) => bytes[offset + index] === character.charCodeAt(0),
  )
}

function littleEndianUint32(bytes: Uint8Array, offset: number): number | null {
  if (bytes.length < offset + 4) return null
  return (
    bytes[offset]! |
    (bytes[offset + 1]! << 8) |
    (bytes[offset + 2]! << 16) |
    (bytes[offset + 3]! << 24)
  ) >>> 0
}

function detectHead(bytes: Uint8Array): MagicMatch | null {
  if (asciiAt(bytes, 0, 'MZ')) {
    const peOffset = littleEndianUint32(bytes, 0x3c)
    if (peOffset !== null && asciiAt(bytes, peOffset, 'PE\u0000\u0000')) {
      return { format: 'PE', allowedCategories: ['binary'] }
    }
  }
  if (startsWith(bytes, [0x7f, 0x45, 0x4c, 0x46])) {
    return { format: 'ELF', allowedCategories: ['binary'] }
  }
  if (
    startsWith(bytes, [0xfe, 0xed, 0xfa, 0xce]) ||
    startsWith(bytes, [0xfe, 0xed, 0xfa, 0xcf]) ||
    startsWith(bytes, [0xce, 0xfa, 0xed, 0xfe]) ||
    startsWith(bytes, [0xcf, 0xfa, 0xed, 0xfe]) ||
    startsWith(bytes, [0xca, 0xfe, 0xba, 0xbe]) ||
    startsWith(bytes, [0xbe, 0xba, 0xfe, 0xca])
  ) {
    return { format: 'Mach-O / Java CLASS', allowedCategories: ['binary'] }
  }
  if (asciiAt(bytes, 0, 'dex\n')) {
    return { format: 'DEX', allowedCategories: ['binary'] }
  }
  if (
    startsWith(bytes, [0x50, 0x4b, 0x03, 0x04]) ||
    startsWith(bytes, [0x50, 0x4b, 0x05, 0x06]) ||
    startsWith(bytes, [0x50, 0x4b, 0x07, 0x08])
  ) {
    return {
      format: 'ZIP / JAR / APK',
      allowedCategories: ['binary', 'archive'],
    }
  }
  if (startsWith(bytes, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) {
    return { format: '7Z', allowedCategories: ['archive'] }
  }
  if (
    startsWith(bytes, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]) ||
    startsWith(bytes, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00])
  ) {
    return { format: 'RAR', allowedCategories: ['archive'] }
  }
  if (startsWith(bytes, [0x1f, 0x8b])) {
    return { format: 'GZIP', allowedCategories: ['archive'] }
  }
  if (asciiAt(bytes, 0, 'BZh')) {
    return { format: 'BZIP2', allowedCategories: ['archive'] }
  }
  if (startsWith(bytes, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) {
    return { format: 'XZ', allowedCategories: ['archive'] }
  }
  if (startsWith(bytes, [0x28, 0xb5, 0x2f, 0xfd])) {
    return { format: 'ZSTD', allowedCategories: ['archive'] }
  }
  if (asciiAt(bytes, 0, 'MSCF')) {
    return { format: 'CAB', allowedCategories: ['archive'] }
  }
  if (
    asciiAt(bytes, 0, '070701') ||
    asciiAt(bytes, 0, '070702') ||
    asciiAt(bytes, 0, '070707')
  ) {
    return { format: 'CPIO', allowedCategories: ['archive'] }
  }
  if (asciiAt(bytes, 0, '!<arch>\n')) {
    return { format: 'AR / DEB', allowedCategories: ['archive'] }
  }
  if (startsWith(bytes, [0xed, 0xab, 0xee, 0xdb])) {
    return { format: 'RPM', allowedCategories: ['archive'] }
  }
  if (asciiAt(bytes, 257, 'ustar')) {
    return {
      format: 'TAR / Docker / OCI',
      allowedCategories: ['archive', 'container'],
    }
  }
  return null
}

function hasZipEndRecord(bytes: Uint8Array): boolean {
  for (let index = Math.max(0, bytes.length - TAIL_LIMIT); index <= bytes.length - 4; index += 1) {
    if (
      bytes[index] === 0x50 &&
      bytes[index + 1] === 0x4b &&
      bytes[index + 2] === 0x05 &&
      bytes[index + 3] === 0x06
    ) {
      return true
    }
  }
  return false
}

function readBlob(blob: Blob): Promise<ArrayBuffer> {
  if (typeof blob.arrayBuffer === 'function') return blob.arrayBuffer()
  return new Promise<ArrayBuffer>((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(reader.error ?? new Error('文件预检读取失败'))
    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) resolve(reader.result)
      else reject(new Error('文件预检读取失败'))
    }
    reader.readAsArrayBuffer(blob)
  })
}

export async function preflightUploadFile(
  file: File,
  category: InputCategory,
): Promise<UploadPreflightResult> {
  const headSlice = file.slice(0, Math.min(file.size, HEAD_LIMIT))
  const tailStart = Math.max(0, file.size - TAIL_LIMIT)
  const tailSlice = file.slice(tailStart, file.size)
  const [headBuffer, tailBuffer] = await Promise.all([
    readBlob(headSlice),
    readBlob(tailSlice),
  ])
  const head = new Uint8Array(headBuffer)
  const tail = new Uint8Array(tailBuffer)
  const match =
    detectHead(head) ??
    (hasZipEndRecord(tail)
      ? {
          format: 'ZIP / JAR / APK',
          allowedCategories: ['binary', 'archive'] as const,
        }
      : null)

  if (!match || match.allowedCategories.includes(category)) {
    return {
      accepted: true,
      ...(match ? { detectedFormat: match.format } : {}),
    }
  }
  return {
    accepted: false,
    detectedFormat: match.format,
    message: `${file.name}：文件内容预检为 ${match.format}，与${inputCategoryLabels[category]}不匹配`,
  }
}
