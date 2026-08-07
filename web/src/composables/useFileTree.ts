import { onScopeDispose, reactive, readonly, toValue, watch, type MaybeRefOrGetter } from 'vue'

import { api, ApiError } from '@/api/client'
import type { FileNode } from '@/api/types'

export const ROOT_FILE_BRANCH = 'root'
const FILE_TREE_PAGE_SIZE = 200

type LoadAction = 'initial' | 'more'

export interface FileTreeBranchState {
  items: FileNode[]
  nextCursor: string | undefined
  loading: boolean
  loaded: boolean
  errorMessage: string
  errorAction: LoadAction | undefined
}

function emptyBranch(): FileTreeBranchState {
  return {
    items: [],
    nextCursor: undefined,
    loading: false,
    loaded: false,
    errorMessage: '',
    errorAction: undefined,
  }
}

export function fileBranchKey(parentId: string): string {
  return `node:${parentId}`
}

export function isExpandableFileNode(node: FileNode): boolean {
  return node.node_type === 'directory' || node.has_children
}

export function useFileTree(taskId: MaybeRefOrGetter<string>) {
  const branches = reactive<Record<string, FileTreeBranchState>>({})
  const expandedNodeIds = reactive(new Set<string>())
  let generation = 0

  function branchKey(parentId: string | null): string {
    return parentId === null ? ROOT_FILE_BRANCH : fileBranchKey(parentId)
  }

  function getOrCreateBranch(parentId: string | null): FileTreeBranchState {
    const key = branchKey(parentId)
    if (!branches[key]) branches[key] = emptyBranch()
    return branches[key]
  }

  function resetState(): void {
    for (const key of Object.keys(branches)) delete branches[key]
    expandedNodeIds.clear()
    branches[ROOT_FILE_BRANCH] = emptyBranch()
  }

  function errorText(error: unknown): string {
    return error instanceof ApiError ? error.message : '文件结构读取失败'
  }

  async function loadBranch(parentId: string | null, append = false): Promise<void> {
    const state = getOrCreateBranch(parentId)
    if (state.loading || (append && !state.nextCursor)) return

    const activeGeneration = generation
    const activeTaskId = toValue(taskId)
    if (!activeTaskId) return

    const cursor = append ? state.nextCursor : undefined
    state.loading = true
    state.errorMessage = ''
    state.errorAction = undefined

    try {
      const page = await api.listTaskFiles(activeTaskId, {
        ...(parentId === null ? {} : { parent_id: parentId }),
        ...(cursor ? { cursor } : {}),
        page_size: FILE_TREE_PAGE_SIZE,
      })
      if (activeGeneration !== generation) return

      if (append) {
        const knownIds = new Set(state.items.map((item) => item.id))
        for (const item of page.items) {
          if (!knownIds.has(item.id)) {
            state.items.push(item)
            knownIds.add(item.id)
          }
        }
      } else {
        state.items = [...page.items]
      }
      state.nextCursor = page.next_cursor
      state.loaded = true
    } catch (error) {
      if (activeGeneration !== generation) return
      state.errorMessage = errorText(error)
      state.errorAction = append ? 'more' : 'initial'
    } finally {
      if (activeGeneration === generation) state.loading = false
    }
  }

  function toggleNode(node: FileNode): void {
    if (!isExpandableFileNode(node)) return
    if (expandedNodeIds.has(node.id)) {
      expandedNodeIds.delete(node.id)
      return
    }

    expandedNodeIds.add(node.id)
    const state = getOrCreateBranch(node.id)
    if (!state.loaded && !state.loading) void loadBranch(node.id)
  }

  function loadMore(parentId: string | null): void {
    void loadBranch(parentId, true)
  }

  function retryBranch(parentId: string | null): void {
    const state = getOrCreateBranch(parentId)
    void loadBranch(parentId, state.errorAction === 'more')
  }

  function reload(): void {
    generation += 1
    resetState()
    void loadBranch(null)
  }

  watch(
    () => toValue(taskId),
    () => reload(),
    { immediate: true },
  )

  onScopeDispose(() => {
    generation += 1
  })

  return {
    branches: readonly(branches),
    expandedNodeIds: readonly(expandedNodeIds),
    toggleNode,
    loadMore,
    retryBranch,
    reload,
  }
}
