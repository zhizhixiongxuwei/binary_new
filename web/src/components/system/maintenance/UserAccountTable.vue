<script setup lang="ts">
import { KeyRound, Pencil } from 'lucide-vue-next'

import type { AdminUser, UserRole } from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import { formatDateTime } from '@/utils/formatters'

defineProps<{
  users: readonly AdminUser[]
  loading: boolean
  loadingMore: boolean
  errorMessage: string
  pendingUserId: string | null
  hasMore: boolean
  canWrite: boolean
  currentUserId: string
}>()

defineEmits<{
  retry: []
  loadMore: []
  edit: [user: AdminUser]
  resetPassword: [user: AdminUser]
}>()

const roleLabels: Readonly<Record<UserRole, string>> = {
  administrator: '系统管理员',
  operator: '操作员',
  reader: '只读用户',
}

const statusLabels: Readonly<Record<AdminUser['status'], string>> = {
  active: '已启用',
  disabled: '已停用',
  locked: '已锁定',
}
</script>

<template>
  <StatePanel v-if="loading" kind="loading" />
  <StatePanel
    v-else-if="errorMessage"
    kind="error"
    :description="errorMessage"
    retryable
    @retry="$emit('retry')"
  />
  <StatePanel v-else-if="!users.length" kind="empty" title="暂无本地用户" />
  <div v-else class="user-table" role="table" aria-label="本地用户列表">
    <div class="user-table__header" role="row">
      <span role="columnheader">用户</span>
      <span role="columnheader">角色</span>
      <span role="columnheader">状态</span>
      <span role="columnheader">安全信息</span>
      <span role="columnheader">最近登录</span>
      <span v-if="canWrite" role="columnheader">操作</span>
    </div>
    <div
      v-for="user in users"
      :key="user.id"
      class="user-row"
      :class="{ 'user-row--self': user.id === currentUserId }"
      role="row"
    >
      <div class="user-identity" role="cell" data-label="用户">
        <span class="avatar" aria-hidden="true">
          {{ (user.display_name || user.username).slice(0, 1).toUpperCase() }}
        </span>
        <span>
          <strong>
            {{ user.display_name }}
            <small v-if="user.id === currentUserId">当前账户</small>
          </strong>
          <code>{{ user.username }}</code>
        </span>
      </div>
      <span role="cell" data-label="角色">
        <span class="role-label">{{ roleLabels[user.role] }}</span>
      </span>
      <span role="cell" data-label="状态">
        <span class="status-label" :class="`status-label--${user.status}`">
          <i aria-hidden="true" />
          {{ statusLabels[user.status] }}
        </span>
      </span>
      <span class="security-meta" role="cell" data-label="安全信息">
        <small v-if="user.must_change_password">首次登录须改密</small>
        <small v-if="user.failed_login_count">
          失败 {{ user.failed_login_count }} 次
        </small>
        <small v-if="user.locked_until">
          锁定至 {{ formatDateTime(user.locked_until) }}
        </small>
        <small v-if="!user.must_change_password && !user.failed_login_count">
          无待处理项
        </small>
      </span>
      <span class="mono login-at" role="cell" data-label="最近登录">
        {{ formatDateTime(user.last_login_at ?? undefined) }}
      </span>
      <div
        v-if="canWrite"
        class="row-actions"
        role="cell"
        data-label="操作"
      >
        <button
          type="button"
          title="编辑用户"
          aria-label="编辑用户"
          :disabled="pendingUserId === user.id"
          @click="$emit('edit', user)"
        >
          <Pencil :size="14" aria-hidden="true" />
        </button>
        <button
          type="button"
          title="重置临时密码"
          aria-label="重置临时密码"
          :disabled="pendingUserId === user.id"
          @click="$emit('resetPassword', user)"
        >
          <KeyRound :size="14" aria-hidden="true" />
        </button>
      </div>
    </div>
  </div>

  <footer v-if="hasMore" class="load-more">
    <button type="button" :disabled="loadingMore" @click="$emit('loadMore')">
      {{ loadingMore ? '正在加载…' : '加载更多用户' }}
    </button>
  </footer>
</template>

<style scoped>
.user-table__header,
.user-row {
  display: grid;
  min-width: 0;
  grid-template-columns:
    minmax(180px, 1.15fr) minmax(100px, 0.55fr) minmax(90px, 0.5fr)
    minmax(125px, 0.7fr) minmax(130px, 0.75fr) 76px;
  align-items: center;
  gap: 12px;
  padding: 10px 17px;
}

.user-table__header {
  color: var(--ink-600);
  background: #f7f9f9;
  font-size: 9px;
  font-weight: 700;
}

.user-row {
  min-height: 66px;
  border-top: 1px solid #e7ebeb;
  color: var(--ink-600);
  font-size: 9px;
}

.user-row--self {
  background: #f7fbfa;
}

.user-identity {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 9px;
}

.avatar {
  display: grid;
  width: 31px;
  height: 31px;
  flex: 0 0 31px;
  place-items: center;
  border: 1px solid #c0d1e4;
  border-radius: 4px;
  color: var(--blue);
  background: #f2f6fa;
  font-size: 10px;
  font-weight: 700;
}

.user-identity > span:last-child {
  min-width: 0;
}

.user-identity strong,
.user-identity code {
  display: block;
  overflow-wrap: anywhere;
}

.user-identity strong {
  color: var(--ink-800);
  font-size: 10px;
}

.user-identity strong small {
  margin-left: 5px;
  color: var(--teal-strong);
  font-size: 8px;
}

.user-identity code {
  margin-top: 2px;
  color: var(--ink-400);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 9px;
}

.role-label,
.status-label {
  display: inline-flex;
  min-height: 22px;
  align-items: center;
  padding: 2px 6px;
  border: 1px solid var(--line);
  border-radius: 3px;
  background: #f7f9f9;
  white-space: nowrap;
}

.status-label {
  gap: 5px;
  border-color: #b8d7d3;
  color: var(--teal-strong);
  background: #f1f8f7;
}

.status-label i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--teal);
}

.status-label--disabled,
.status-label--locked {
  border-color: #decba7;
  color: var(--amber);
  background: #fff9ef;
}

.status-label--disabled i,
.status-label--locked i {
  background: var(--amber);
}

.security-meta small {
  display: block;
  color: var(--ink-600);
  font-size: 8px;
  overflow-wrap: anywhere;
}

.security-meta small + small {
  margin-top: 2px;
}

.login-at {
  overflow-wrap: anywhere;
}

.row-actions {
  display: flex;
  gap: 5px;
}

.row-actions button {
  display: inline-grid;
  width: 30px;
  height: 30px;
  place-items: center;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
}

.row-actions button:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.load-more {
  display: grid;
  place-items: center;
  padding: 10px;
  border-top: 1px solid var(--line);
}

.load-more button {
  min-height: 32px;
  padding: 5px 10px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
  font-size: 10px;
}

@container users-live (max-width: 900px) {
  .user-table__header {
    display: none;
  }

  .user-row {
    grid-template-columns: minmax(190px, 1fr) repeat(2, minmax(100px, 0.5fr));
  }

  .user-row > [role="cell"]:not(.user-identity)::before {
    display: block;
    margin-bottom: 5px;
    color: var(--ink-400);
    content: attr(data-label);
    font-size: 8px;
  }
}

@container users-live (max-width: 620px) {
  .user-row {
    grid-template-columns: 1fr 1fr;
    padding: 13px;
  }

  .user-identity {
    grid-column: 1 / -1;
  }
}

@container users-live (max-width: 420px) {
  .user-row {
    grid-template-columns: 1fr;
  }

  .user-identity {
    grid-column: auto;
  }
}
</style>
