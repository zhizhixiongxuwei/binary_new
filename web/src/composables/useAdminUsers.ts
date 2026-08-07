import { readonly, shallowRef } from 'vue'

import { api, ApiError } from '@/api/client'
import type {
  AdminUser,
  AdminUserListQuery,
  CreateAdminUserInput,
  ResetAdminUserPasswordInput,
  UpdateAdminUserInput,
} from '@/api/types'

const PAGE_SIZE = 50

export function useAdminUsers() {
  const users = shallowRef<AdminUser[]>([])
  const query = shallowRef<AdminUserListQuery>({})
  const nextCursor = shallowRef<string | undefined>()
  const loading = shallowRef(false)
  const loadingMore = shallowRef(false)
  const errorMessage = shallowRef('')
  const operationError = shallowRef('')
  const pendingUserId = shallowRef<string | null>(null)
  const operationSucceededId = shallowRef<string | null>(null)
  let requestSequence = 0

  function replaceUser(updated: AdminUser): void {
    const index = users.value.findIndex((user) => user.id === updated.id)
    users.value =
      index === -1
        ? [updated, ...users.value]
        : users.value.map((user) => (user.id === updated.id ? updated : user))
  }

  async function load(options: { append?: boolean } = {}): Promise<void> {
    const append = options.append === true
    if (append && (!nextCursor.value || loadingMore.value)) return
    const sequence = ++requestSequence
    if (append) loadingMore.value = true
    else loading.value = true
    errorMessage.value = ''
    try {
      const cursor = append ? nextCursor.value : undefined
      const page = await api.listAdminUsers({
        ...query.value,
        ...(cursor ? { cursor } : {}),
        page_size: PAGE_SIZE,
      })
      if (sequence !== requestSequence) return
      users.value = append ? [...users.value, ...page.items] : page.items
      nextCursor.value = page.next_cursor
    } catch (error) {
      if (sequence === requestSequence) {
        errorMessage.value =
          error instanceof ApiError ? error.message : '用户列表读取失败'
      }
    } finally {
      if (sequence === requestSequence) {
        loading.value = false
        loadingMore.value = false
      }
    }
  }

  async function search(nextQuery: AdminUserListQuery): Promise<void> {
    query.value = { ...nextQuery }
    await load()
  }

  async function runMutation(
    userId: string,
    mutation: () => Promise<AdminUser>,
  ): Promise<boolean> {
    pendingUserId.value = userId
    operationError.value = ''
    operationSucceededId.value = null
    try {
      replaceUser(await mutation())
      operationSucceededId.value = userId
      return true
    } catch (error) {
      operationError.value =
        error instanceof ApiError ? error.message : '用户操作失败'
      return false
    } finally {
      pendingUserId.value = null
    }
  }

  async function create(input: CreateAdminUserInput): Promise<boolean> {
    return runMutation('new', () => api.createAdminUser(input))
  }

  async function update(
    userId: string,
    input: UpdateAdminUserInput,
  ): Promise<boolean> {
    return runMutation(userId, () => api.updateAdminUser(userId, input))
  }

  async function resetPassword(
    userId: string,
    input: ResetAdminUserPasswordInput,
  ): Promise<boolean> {
    return runMutation(userId, () =>
      api.resetAdminUserPassword(userId, input),
    )
  }

  function clearOperationError(): void {
    operationError.value = ''
  }

  return {
    users: readonly(users),
    query: readonly(query),
    nextCursor: readonly(nextCursor),
    loading: readonly(loading),
    loadingMore: readonly(loadingMore),
    errorMessage: readonly(errorMessage),
    operationError: readonly(operationError),
    pendingUserId: readonly(pendingUserId),
    operationSucceededId: readonly(operationSucceededId),
    load,
    search,
    create,
    update,
    resetPassword,
    clearOperationError,
  }
}
