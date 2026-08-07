<script setup lang="ts">
import {
  LockKeyhole,
  Plus,
  RefreshCw,
  ShieldCheck,
  UserRound,
} from 'lucide-vue-next'
import { computed, shallowRef } from 'vue'

import type {
  AdminUser,
  AdminUserListQuery,
  CreateAdminUserInput,
  ResetAdminUserPasswordInput,
  UpdateAdminUserInput,
  UserRole,
} from '@/api/types'
import UserAccountDialog, {
  type UserDialogMode,
} from '@/components/system/maintenance/UserAccountDialog.vue'
import UserAccountTable from '@/components/system/maintenance/UserAccountTable.vue'
import UserFilterBar from '@/components/system/maintenance/UserFilterBar.vue'

const props = defineProps<{
  users: readonly AdminUser[]
  loading: boolean
  loadingMore: boolean
  errorMessage: string
  operationError: string
  pendingUserId: string | null
  operationSucceededId: string | null
  hasMore: boolean
  currentUserId: string
  currentRole: UserRole
}>()

const emit = defineEmits<{
  retry: []
  search: [query: AdminUserListQuery]
  loadMore: []
  create: [input: CreateAdminUserInput]
  update: [userId: string, input: UpdateAdminUserInput]
  resetPassword: [userId: string, input: ResetAdminUserPasswordInput]
  dismissOperationError: []
}>()

const dialogMode = shallowRef<UserDialogMode | null>(null)
const selectedUser = shallowRef<AdminUser | null>(null)
const canWrite = computed(() => props.currentRole === 'administrator')

function openDialog(mode: UserDialogMode, user: AdminUser | null = null): void {
  selectedUser.value = user
  dialogMode.value = mode
  emit('dismissOperationError')
}

function closeDialog(): void {
  dialogMode.value = null
  selectedUser.value = null
  emit('dismissOperationError')
}
</script>

<template>
  <section
    class="user-management surface-panel"
    aria-labelledby="user-management-title"
  >
    <header class="section-heading">
      <div>
        <span class="section-kicker mono">LIVE / LOCAL RBAC</span>
        <h2 id="user-management-title">本地用户与角色</h2>
        <p>账户变更写入本地数据库；角色权限仍由服务端强制校验。</p>
      </div>
      <div class="heading-actions">
        <button
          type="button"
          class="icon-button"
          title="刷新用户列表"
          aria-label="刷新用户列表"
          :disabled="loading"
          @click="$emit('retry')"
        >
          <RefreshCw :size="16" aria-hidden="true" />
        </button>
        <button
          v-if="canWrite"
          type="button"
          class="primary-command"
          @click="openDialog('create')"
        >
          <Plus :size="15" aria-hidden="true" />
          新增用户
        </button>
      </div>
    </header>

    <div class="role-strip" aria-label="本地角色权限摘要">
      <span>
        <LockKeyhole :size="14" aria-hidden="true" />
        <strong>管理员</strong>
        平台维护与用户管理
      </span>
      <span>
        <ShieldCheck :size="14" aria-hidden="true" />
        <strong>操作员</strong>
        创建和操作检测任务
      </span>
      <span>
        <UserRound :size="14" aria-hidden="true" />
        <strong>只读用户</strong>
        查看任务、结果和报告
      </span>
    </div>

    <UserFilterBar :loading="loading" @search="$emit('search', $event)" />
    <UserAccountTable
      :users="users"
      :loading="loading"
      :loading-more="loadingMore"
      :error-message="errorMessage"
      :pending-user-id="pendingUserId"
      :has-more="hasMore"
      :can-write="canWrite"
      :current-user-id="currentUserId"
      @retry="$emit('retry')"
      @load-more="$emit('loadMore')"
      @edit="openDialog('edit', $event)"
      @reset-password="openDialog('reset', $event)"
    />

    <UserAccountDialog
      v-if="dialogMode"
      :mode="dialogMode"
      :user="selectedUser"
      :current-user-id="currentUserId"
      :pending="pendingUserId !== null"
      :operation-error="operationError"
      :operation-succeeded-id="operationSucceededId"
      @close="closeDialog"
      @create="$emit('create', $event)"
      @update="(userId, input) => $emit('update', userId, input)"
      @reset-password="
        (userId, input) => $emit('resetPassword', userId, input)
      "
    />
  </section>
</template>

<style scoped>
.user-management {
  min-width: 0;
  overflow: hidden;
  container: users-live / inline-size;
}

.section-heading {
  display: flex;
  min-height: 76px;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 14px 17px;
  border-bottom: 1px solid var(--line);
}

.section-heading > div {
  min-width: 0;
}

.section-kicker {
  display: block;
  margin-bottom: 5px;
  color: var(--teal-strong);
  font-size: 9px;
  font-weight: 700;
}

.section-heading h2,
.section-heading p {
  margin: 0;
}

.section-heading h2 {
  color: var(--ink-800);
  font-size: 14px;
}

.section-heading p {
  margin-top: 5px;
  color: var(--ink-600);
  font-size: 10px;
}

.heading-actions {
  display: flex;
  flex: 0 0 auto;
  gap: 7px;
}

.heading-actions button {
  display: inline-grid;
  width: 32px;
  height: 32px;
  place-items: center;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
}

.heading-actions .primary-command {
  display: inline-flex;
  width: auto;
  align-items: center;
  gap: 6px;
  padding: 5px 10px;
  border-color: var(--teal);
  color: #fff;
  background: var(--teal);
  font-size: 10px;
}

.heading-actions button:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.role-strip {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  border-bottom: 1px solid var(--line);
  background: #f7f9f9;
}

.role-strip > span {
  display: flex;
  min-width: 0;
  min-height: 42px;
  align-items: center;
  gap: 6px;
  padding: 8px 17px;
  border-right: 1px solid var(--line);
  color: var(--ink-600);
  font-size: 9px;
  overflow-wrap: anywhere;
}

.role-strip > span:last-child {
  border-right: 0;
}

.role-strip svg {
  flex: 0 0 auto;
  color: var(--blue);
}

.role-strip strong {
  color: var(--ink-800);
  white-space: nowrap;
}

@container users-live (max-width: 620px) {
  .section-heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .heading-actions {
    width: 100%;
    justify-content: flex-end;
  }

  .role-strip {
    grid-template-columns: 1fr;
  }

  .role-strip > span {
    border-right: 0;
    border-bottom: 1px solid var(--line);
  }
}
</style>
