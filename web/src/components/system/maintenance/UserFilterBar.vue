<script setup lang="ts">
import { Search } from 'lucide-vue-next'
import { reactive } from 'vue'

import type {
  AdminUser,
  AdminUserListQuery,
  UserRole,
} from '@/api/types'

defineProps<{
  loading: boolean
}>()

const emit = defineEmits<{
  search: [query: AdminUserListQuery]
}>()

const filters = reactive({
  keyword: '',
  role: '',
  status: '',
})

function submit(): void {
  const keyword = filters.keyword.trim()
  emit('search', {
    ...(keyword ? { keyword } : {}),
    ...(filters.role ? { role: filters.role as UserRole } : {}),
    ...(filters.status
      ? { status: filters.status as AdminUser['status'] }
      : {}),
  })
}

function clear(): void {
  filters.keyword = ''
  filters.role = ''
  filters.status = ''
  emit('search', {})
}
</script>

<template>
  <form class="user-filters" @submit.prevent="submit">
    <label>
      <span>用户</span>
      <input
        v-model="filters.keyword"
        placeholder="用户名或显示名称"
        maxlength="100"
      >
    </label>
    <label>
      <span>角色</span>
      <select v-model="filters.role">
        <option value="">全部角色</option>
        <option value="administrator">系统管理员</option>
        <option value="operator">操作员</option>
        <option value="reader">只读用户</option>
      </select>
    </label>
    <label>
      <span>状态</span>
      <select v-model="filters.status">
        <option value="">全部状态</option>
        <option value="active">已启用</option>
        <option value="disabled">已停用</option>
        <option value="locked">已锁定</option>
      </select>
    </label>
    <div>
      <button type="button" :disabled="loading" @click="clear">清除</button>
      <button class="filter-submit" type="submit" :disabled="loading">
        <Search :size="14" aria-hidden="true" />
        查询
      </button>
    </div>
  </form>
</template>

<style scoped>
.user-filters {
  display: grid;
  grid-template-columns: minmax(180px, 1fr) minmax(120px, 0.45fr) minmax(120px, 0.45fr) auto;
  align-items: end;
  gap: 9px;
  padding: 10px 17px;
  border-bottom: 1px solid var(--line);
  background: #fbfcfc;
}

.user-filters label {
  display: grid;
  min-width: 0;
  gap: 4px;
}

.user-filters label > span {
  color: var(--ink-600);
  font-size: 8px;
  font-weight: 700;
}

.user-filters input,
.user-filters select {
  width: 100%;
  min-width: 0;
  min-height: 32px;
  padding: 5px 7px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-800);
  background: var(--surface);
  font-size: 9px;
}

.user-filters > div {
  display: flex;
  gap: 6px;
}

.user-filters button {
  display: inline-flex;
  min-height: 32px;
  align-items: center;
  justify-content: center;
  gap: 5px;
  padding: 5px 9px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
  font-size: 9px;
}

.user-filters .filter-submit {
  border-color: var(--teal);
  color: #fff;
  background: var(--teal);
}

.user-filters button:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

@container users-live (max-width: 900px) {
  .user-filters {
    grid-template-columns: minmax(180px, 1fr) repeat(2, minmax(100px, 0.5fr));
  }

  .user-filters > div {
    grid-column: 1 / -1;
    justify-content: flex-end;
  }
}

@container users-live (max-width: 620px) {
  .user-filters {
    grid-template-columns: 1fr;
    padding: 13px;
  }

  .user-filters > div {
    grid-column: auto;
  }
}
</style>
