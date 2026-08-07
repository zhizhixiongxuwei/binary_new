<script setup lang="ts">
import { LockKeyhole, UserPlus, UsersRound } from 'lucide-vue-next'

import MaintenanceUnavailable from '@/components/system/maintenance/MaintenanceUnavailable.vue'
import {
  rolePreviews,
  userPreviews,
  type MaintenanceViewMode,
  type RolePreview,
  type UserPreview,
} from '@/components/system/maintenance/maintenanceFixtures'

defineProps<{
  mode: MaintenanceViewMode
}>()

const roleLabels: Readonly<Record<RolePreview['id'], string>> = {
  administrator: '系统管理员',
  operator: '操作员',
  reader: '只读用户',
}

const userStateLabels: Readonly<Record<UserPreview['state'], string>> = {
  enabled: '已启用',
  locked: '已锁定',
}
</script>

<template>
  <MaintenanceUnavailable
    v-if="mode === 'live'"
    title="用户维护接口未接入"
    description="后端尚未提供用户和角色管理接口，本页不会读取、创建或修改真实账户。"
  />

  <div v-else class="access-panel">
    <section class="role-panel surface-panel" aria-labelledby="role-title">
      <header class="panel-heading">
        <div>
          <span class="preview-kicker mono">FIXED PREVIEW / RBAC</span>
          <h2 id="role-title">角色权限边界</h2>
          <p>角色名称和权限项为当前界面设计样例，不代表已完成后端授权模型。</p>
        </div>
        <span class="preview-badge">固定示例</span>
      </header>

      <div class="role-grid">
        <article v-for="role in rolePreviews" :key="role.id" class="role-card">
          <div class="role-card__title">
            <span aria-hidden="true"><LockKeyhole :size="16" /></span>
            <div>
              <strong>{{ role.label }}</strong>
              <code>{{ role.id }}</code>
            </div>
          </div>
          <p>{{ role.scope }}</p>
          <ul :aria-label="`${role.label}权限预览`">
            <li v-for="permission in role.permissions" :key="permission">
              {{ permission }}
            </li>
          </ul>
        </article>
      </div>
    </section>

    <section class="user-panel surface-panel" aria-labelledby="user-title">
      <header class="user-panel__toolbar">
        <div>
          <span class="preview-kicker mono">FIXED PREVIEW / LOCAL USERS</span>
          <h2 id="user-title">本地用户</h2>
        </div>
        <div class="user-command">
          <button type="button" disabled title="后端未接入">
            <UserPlus :size="15" aria-hidden="true" />
            新增用户
          </button>
          <span>命令不可用：后端未接入</span>
        </div>
      </header>

      <div class="user-table" role="table" aria-label="固定示例用户列表">
        <div class="user-table__header" role="row">
          <span role="columnheader">用户</span>
          <span role="columnheader">角色</span>
          <span role="columnheader">状态</span>
          <span role="columnheader">最近活动</span>
        </div>
        <div
          v-for="user in userPreviews"
          :key="user.username"
          class="user-row"
          role="row"
        >
          <div class="user-identity" role="cell" data-label="用户">
            <span class="user-avatar" aria-hidden="true">
              <UsersRound :size="15" />
            </span>
            <div>
              <strong>{{ user.displayName }}</strong>
              <code>{{ user.username }}</code>
            </div>
          </div>
          <span role="cell" data-label="角色">
            <span class="role-label">{{ roleLabels[user.role] }}</span>
          </span>
          <span role="cell" data-label="状态">
            <span class="user-state" :class="`user-state--${user.state}`">
              <i aria-hidden="true" />
              {{ userStateLabels[user.state] }}
            </span>
          </span>
          <span class="mono last-active" role="cell" data-label="最近活动">
            {{ user.lastActive }}
          </span>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.access-panel {
  display: grid;
  min-width: 0;
  gap: 14px;
  container: access-panel / inline-size;
}

.panel-heading,
.user-panel__toolbar {
  display: flex;
  min-height: 66px;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 14px 17px;
  border-bottom: 1px solid var(--line);
}

.panel-heading > div,
.user-panel__toolbar > div {
  min-width: 0;
}

.preview-kicker {
  display: block;
  margin-bottom: 5px;
  color: var(--teal-strong);
  font-size: 9px;
  font-weight: 700;
}

.panel-heading h2,
.panel-heading p,
.user-panel__toolbar h2 {
  margin: 0;
}

.panel-heading h2,
.user-panel__toolbar h2 {
  color: var(--ink-800);
  font-size: 14px;
}

.panel-heading p {
  margin-top: 5px;
  color: var(--ink-600);
  font-size: 10px;
  line-height: 1.6;
}

.preview-badge {
  flex: 0 0 auto;
  padding: 4px 7px;
  border: 1px solid #b8d7d3;
  border-radius: 3px;
  color: var(--teal-strong);
  background: #f1f8f7;
  font-size: 10px;
  font-weight: 700;
  white-space: nowrap;
}

.role-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.role-card {
  min-width: 0;
  min-height: 164px;
  padding: 15px 16px;
  border-right: 1px solid #e7ebeb;
}

.role-card:last-child {
  border-right: 0;
}

.role-card__title {
  display: flex;
  align-items: center;
  gap: 9px;
}

.role-card__title > span {
  display: grid;
  width: 30px;
  height: 30px;
  flex: 0 0 30px;
  place-items: center;
  border: 1px solid #c0d1e4;
  border-radius: 4px;
  color: var(--blue);
  background: #f2f6fa;
}

.role-card__title strong,
.role-card__title code {
  display: block;
}

.role-card__title strong {
  color: var(--ink-800);
  font-size: 11px;
}

.role-card__title code {
  margin-top: 2px;
  color: var(--ink-400);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 9px;
  overflow-wrap: anywhere;
}

.role-card > p {
  min-height: 32px;
  margin: 11px 0 9px;
  color: var(--ink-600);
  font-size: 9px;
  line-height: 1.6;
}

.role-card ul {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  padding: 0;
  margin: 0;
  list-style: none;
}

.role-card li {
  padding: 3px 6px;
  border: 1px solid var(--line);
  border-radius: 3px;
  color: var(--ink-600);
  background: #f7f9f9;
  font-size: 9px;
}

.user-panel__toolbar {
  align-items: center;
}

.user-command {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
}

.user-command button {
  display: inline-flex;
  min-height: 32px;
  align-items: center;
  gap: 6px;
  padding: 5px 9px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-400);
  background: #eef1f1;
  font-size: 10px;
  cursor: not-allowed;
}

.user-command span {
  color: var(--ink-400);
  font-size: 9px;
}

.user-table {
  min-width: 0;
}

.user-table__header,
.user-row {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(190px, 1.2fr) minmax(120px, 0.7fr) minmax(100px, 0.5fr) minmax(150px, 0.8fr);
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
  min-height: 58px;
  border-top: 1px solid #e7ebeb;
  color: var(--ink-600);
  font-size: 10px;
}

.user-identity {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 9px;
}

.user-avatar {
  display: grid;
  width: 30px;
  height: 30px;
  flex: 0 0 30px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface-raised);
}

.user-identity > div {
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

.user-identity code {
  margin-top: 2px;
  color: var(--ink-400);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 9px;
}

.role-label,
.user-state {
  display: inline-flex;
  min-height: 22px;
  align-items: center;
  padding: 2px 6px;
  border: 1px solid var(--line);
  border-radius: 3px;
  color: var(--ink-600);
  background: #f7f9f9;
  font-size: 9px;
  white-space: nowrap;
}

.user-state {
  gap: 5px;
  border-color: #b8d7d3;
  color: var(--teal-strong);
  background: #f1f8f7;
}

.user-state i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--teal);
}

.user-state--locked {
  border-color: #decba7;
  color: var(--amber);
  background: #fff9ef;
}

.user-state--locked i {
  background: var(--amber);
}

.last-active {
  min-width: 0;
  overflow-wrap: anywhere;
}

@container access-panel (max-width: 760px) {
  .role-grid {
    grid-template-columns: 1fr;
  }

  .role-card {
    min-height: 0;
    border-right: 0;
    border-bottom: 1px solid #e7ebeb;
  }

  .role-card:last-child {
    border-bottom: 0;
  }

  .role-card > p {
    min-height: 0;
  }

  .user-table__header {
    display: none;
  }

  .user-row {
    grid-template-columns: 1fr;
    gap: 8px;
    padding: 13px;
  }

  .user-row > [role="cell"]:not(.user-identity) {
    display: grid;
    grid-template-columns: 76px minmax(0, 1fr);
    align-items: center;
    gap: 8px;
  }

  .user-row > [role="cell"]:not(.user-identity)::before {
    color: var(--ink-400);
    font-size: 9px;
    content: attr(data-label);
  }
}

@container access-panel (max-width: 520px) {
  .panel-heading,
  .user-panel__toolbar {
    align-items: flex-start;
    flex-direction: column;
    gap: 9px;
    padding: 13px;
  }

  .user-command {
    width: 100%;
    align-items: stretch;
    flex-direction: column;
  }

  .user-command button {
    justify-content: center;
  }
}
</style>
