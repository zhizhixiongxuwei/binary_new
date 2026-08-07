import {
  onScopeDispose,
  readonly,
  shallowRef,
  toValue,
  watch,
  type MaybeRefOrGetter,
} from 'vue'

import {
  api,
  ApiError,
  safeReportDownloadFilename,
} from '@/api/client'
import type {
  ReportDownloadEncoding,
  TaskReport,
} from '@/api/types'

interface UseReportDownloadOptions {
  taskId: MaybeRefOrGetter<string>
  enabled?: MaybeRefOrGetter<boolean>
}

const BLOB_URL_RELEASE_DELAY_MS = 30_000

function errorMessage(error: unknown): string {
  if (error instanceof ApiError || error instanceof Error) return error.message
  return '未知错误'
}

export function reportDownloadKey(
  reportId: string,
  encoding: ReportDownloadEncoding,
): string {
  return `${reportId}:${encoding}`
}

export function useReportDownload(options: UseReportDownloadOptions) {
  const pendingKey = shallowRef('')
  const error = shallowRef('')
  const blobReleaseTimers = new Map<
    string,
    ReturnType<typeof globalThis.setTimeout>
  >()
  let scopeGeneration = 0

  function isEnabled(): boolean {
    return options.enabled === undefined || toValue(options.enabled)
  }

  function clickDownload(url: string, filename?: string): void {
    if (typeof document === 'undefined') {
      throw new Error('当前浏览器不支持报告下载')
    }
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename ?? ''
    anchor.rel = 'noopener'
    anchor.style.display = 'none'
    document.body.append(anchor)
    anchor.click()
    anchor.remove()
  }

  function scheduleBlobRelease(objectUrl: string): void {
    const timer = globalThis.setTimeout(() => {
      blobReleaseTimers.delete(objectUrl)
      URL.revokeObjectURL(objectUrl)
    }, BLOB_URL_RELEASE_DELAY_MS)
    blobReleaseTimers.set(objectUrl, timer)
  }

  function clearError(): void {
    error.value = ''
  }

  async function download(
    report: TaskReport,
    encoding: ReportDownloadEncoding = 'identity',
  ): Promise<void> {
    const taskId = toValue(options.taskId)
    if (
      !taskId ||
      !isEnabled() ||
      report.task_id !== taskId ||
      report.status !== 'complete' ||
      pendingKey.value
    ) {
      return
    }
    if (encoding === 'gzip' && report.format !== 'json') {
      error.value = '只有 JSON 报告支持 gzip 压缩下载。'
      return
    }

    const currentScope = scopeGeneration
    pendingKey.value = reportDownloadKey(report.id, encoding)
    error.value = ''

    try {
      const result = await api.downloadTaskReport(
        taskId,
        report.id,
        report.format,
        encoding,
      )
      if (
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId)
      ) {
        return
      }
      if (result.kind === 'url') {
        if (typeof window === 'undefined') {
          throw new Error('当前浏览器不支持报告下载')
        }
        const target = new URL(result.url, window.location.href)
        if (
          target.origin !== window.location.origin ||
          target.username ||
          target.password
        ) {
          throw new Error('报告下载地址不是安全的同源地址')
        }
        clickDownload(target.href)
        return
      }
      if (typeof URL.createObjectURL !== 'function') {
        throw new Error('当前浏览器不支持报告下载')
      }
      const objectUrl = URL.createObjectURL(result.blob)
      scheduleBlobRelease(objectUrl)
      clickDownload(
        objectUrl,
        safeReportDownloadFilename(
          result.filename,
          report.format,
          encoding,
        ),
      )
    } catch (caught) {
      if (
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId)
      ) {
        return
      }
      error.value = `下载 ${report.format.toUpperCase()}${
        encoding === 'gzip' ? '.GZ' : ''
      } 报告失败：${errorMessage(caught)}`
    } finally {
      if (currentScope === scopeGeneration) pendingKey.value = ''
    }
  }

  async function downloadSources(includeCombined: boolean): Promise<void> {
    const taskId = toValue(options.taskId)
    if (!taskId || !isEnabled() || pendingKey.value) return

    const currentScope = scopeGeneration
    pendingKey.value = `decompile-sources:${includeCombined ? 'combined' : 'functions'}`
    error.value = ''

    try {
      const result = await api.downloadDecompileSources(
        taskId,
        includeCombined,
      )
      if (
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId)
      ) {
        return
      }
      if (result.kind === 'url') {
        if (typeof window === 'undefined') {
          throw new Error('当前浏览器不支持源码包下载')
        }
        const target = new URL(result.url, window.location.href)
        if (
          target.origin !== window.location.origin ||
          target.username ||
          target.password
        ) {
          throw new Error('源码包下载地址不是安全的同源地址')
        }
        clickDownload(target.href)
        return
      }
      if (typeof URL.createObjectURL !== 'function') {
        throw new Error('当前浏览器不支持源码包下载')
      }
      const objectUrl = URL.createObjectURL(result.blob)
      scheduleBlobRelease(objectUrl)
      clickDownload(objectUrl, 'binaryscan-decompile-sources.zip')
    } catch (caught) {
      if (
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId)
      ) {
        return
      }
      error.value = `导出反编译源码包失败：${errorMessage(caught)}`
    } finally {
      if (currentScope === scopeGeneration) pendingKey.value = ''
    }
  }

  watch(
    [
      () => toValue(options.taskId),
      () => isEnabled(),
    ],
    () => {
      scopeGeneration += 1
      pendingKey.value = ''
      error.value = ''
    },
    { immediate: true },
  )

  onScopeDispose(() => {
    scopeGeneration += 1
    for (const [objectUrl, timer] of blobReleaseTimers) {
      globalThis.clearTimeout(timer)
      URL.revokeObjectURL(objectUrl)
    }
    blobReleaseTimers.clear()
  })

  return {
    pendingKey: readonly(pendingKey),
    error: readonly(error),
    clearError,
    download,
    downloadSources,
  }
}
