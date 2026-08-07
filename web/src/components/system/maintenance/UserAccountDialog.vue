<script setup lang="ts">
import { X } from 'lucide-vue-next'
import { computed, reactive, shallowRef, watch } from 'vue'

import type {
  AdminUser,
  CreateAdminUserInput,
  ResetAdminUserPasswordInput,
  UpdateAdminUserInput,
  UserRole,
} from '@/api/types'

export type UserDialogMode = 'create' | 'edit' | 'reset'

const props = defineProps<{
  mode: UserDialogMode
  user: AdminUser | null
  currentUserId: string
  pending: boolean
  operationError: string
  operationSucceededId: string | null
}>()

const emit = defineEmits<{
  close: []
  create: [input: CreateAdminUserInput]
  update: [userId: string, input: UpdateAdminUserInput]
  resetPassword: [userId: string, input: ResetAdminUserPasswordInput]
}>()

const formError = shallowRef('')
const passwordEncoder = new TextEncoder()
const createForm = reactive({
  username: '',
  displayName: '',
  role: 'operator' as UserRole,
  temporaryPassword: '',
})
const editForm = reactive({
  role: 'operator' as UserRole,
  status: 'active' as 'active' | 'disabled',
  unlockLocked: false,
})
const resetForm = reactive({
  temporaryPassword: '',
})

const title = computed(() => {
  if (props.mode === 'create') return '创建本地用户'
  if (props.mode === 'edit') return '更新用户'
  return '重置临时密码'
})

function clearSensitiveForms(): void {
  createForm.temporaryPassword = ''
  resetForm.temporaryPassword = ''
}

function close(): void {
  if (props.pending) return
  formError.value = ''
  clearSensitiveForms()
  emit('close')
}

function resetFormState(): void {
  formError.value = ''
  clearSensitiveForms()
  if (props.mode === 'create') {
    createForm.username = ''
    createForm.displayName = ''
    createForm.role = 'operator'
    return
  }
  if (props.user) {
    editForm.role = props.user.role
    editForm.status = props.user.status === 'disabled' ? 'disabled' : 'active'
    editForm.unlockLocked = false
  }
}

function validTemporaryPassword(value: string): boolean {
  const byteLength = passwordEncoder.encode(value).byteLength
  return byteLength >= 12 && byteLength <= 1024
}

function submitCreate(): void {
  const username = createForm.username.trim()
  const displayName = createForm.displayName.trim()
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/.test(username)) {
    formError.value = '用户名需为 1 至 64 位，且以字母或数字开头'
    return
  }
  if (!displayName || displayName.length > 128) {
    formError.value = '显示名称不能为空且不能超过 128 个字符'
    return
  }
  if (!validTemporaryPassword(createForm.temporaryPassword)) {
    formError.value = '临时密码长度需为 12 至 1024 字节'
    return
  }
  formError.value = ''
  emit('create', {
    username,
    display_name: displayName,
    role: createForm.role,
    temporary_password: createForm.temporaryPassword,
  })
}

function submitEdit(): void {
  const user = props.user
  if (!user) return
  const isSelf = user.id === props.currentUserId
  formError.value = ''
  emit('update', user.id, {
    role: isSelf ? user.role : editForm.role,
    ...(user.status === 'locked'
      ? editForm.unlockLocked
        ? { status: 'active' as const }
        : {}
      : { status: isSelf ? 'active' as const : editForm.status }),
    expected_updated_at: user.updated_at,
  })
}

function submitReset(): void {
  const user = props.user
  if (!user) return
  if (!validTemporaryPassword(resetForm.temporaryPassword)) {
    formError.value = '临时密码长度需为 12 至 1024 字节'
    return
  }
  formError.value = ''
  emit('resetPassword', user.id, {
    temporary_password: resetForm.temporaryPassword,
    expected_updated_at: user.updated_at,
  })
}

watch(
  () => [props.mode, props.user?.id] as const,
  resetFormState,
  { immediate: true },
)

watch(
  () => props.operationSucceededId,
  (succeededId) => {
    if (
      (props.mode === 'create' && succeededId === 'new') ||
      (props.user && props.user.id === succeededId)
    ) {
      close()
    }
  },
)
</script>

<template>
  <div
    class="dialog-backdrop"
    role="presentation"
    @mousedown.self="close"
  >
    <section
      class="user-dialog"
      role="dialog"
      aria-modal="true"
      :aria-labelledby="`user-dialog-${mode}`"
    >
      <header>
        <div>
          <span class="dialog-kicker mono">CONFIRM / LOCAL ACCOUNT</span>
          <h3 :id="`user-dialog-${mode}`">{{ title }}</h3>
        </div>
        <button
          type="button"
          title="关闭"
          aria-label="关闭"
          :disabled="pending"
          @click="close"
        >
          <X :size="16" aria-hidden="true" />
        </button>
      </header>

      <form v-if="mode === 'create'" @submit.prevent="submitCreate">
        <label>
          <span>用户名</span>
          <input
            v-model="createForm.username"
            autocomplete="off"
            maxlength="64"
            required
          >
        </label>
        <label>
          <span>显示名称</span>
          <input v-model="createForm.displayName" maxlength="128" required>
        </label>
        <label>
          <span>角色</span>
          <select v-model="createForm.role">
            <option value="administrator">系统管理员</option>
            <option value="operator">操作员</option>
            <option value="reader">只读用户</option>
          </select>
        </label>
        <label>
          <span>临时密码</span>
          <input
            v-model="createForm.temporaryPassword"
            type="password"
            autocomplete="new-password"
            maxlength="1024"
            required
          >
          <small>仅提交给服务端，不在确认信息或列表中回显。</small>
        </label>
        <p class="confirmation-note">
          创建后该账户首次登录必须修改密码。请确认用户名与角色无误。
        </p>
        <p v-if="formError || operationError" class="form-error" role="alert">
          {{ formError || operationError }}
        </p>
        <footer>
          <button type="button" :disabled="pending" @click="close">取消</button>
          <button class="confirm-command" type="submit" :disabled="pending">
            {{ pending ? '正在创建…' : '确认创建' }}
          </button>
        </footer>
      </form>

      <form v-else-if="mode === 'edit'" @submit.prevent="submitEdit">
        <div class="dialog-subject">
          <strong>{{ user?.display_name }}</strong>
          <code>{{ user?.username }}</code>
        </div>
        <label>
          <span>角色</span>
          <select
            v-model="editForm.role"
            :disabled="user?.id === currentUserId"
          >
            <option value="administrator">系统管理员</option>
            <option value="operator">操作员</option>
            <option value="reader">只读用户</option>
          </select>
          <small v-if="user?.id === currentUserId">
            不能降级当前登录账户。
          </small>
        </label>
        <label>
          <span>账户状态</span>
          <select
            v-if="user?.status !== 'locked'"
            v-model="editForm.status"
            :disabled="user?.id === currentUserId"
          >
            <option value="active">启用</option>
            <option value="disabled">停用</option>
          </select>
          <small v-if="user?.id === currentUserId">
            不能停用当前登录账户。
          </small>
          <span v-if="user?.status === 'locked'" class="locked-edit-control">
            <input v-model="editForm.unlockLocked" type="checkbox">
            <span>本次保存同时解锁该账户</span>
          </span>
          <small v-if="user?.status === 'locked'">
            不勾选时只更新角色，账户保持锁定。
          </small>
        </label>
        <p class="confirmation-note">
          此操作使用更新时间进行并发校验，账户已被他人修改时不会覆盖。
        </p>
        <p v-if="formError || operationError" class="form-error" role="alert">
          {{ formError || operationError }}
        </p>
        <footer>
          <button type="button" :disabled="pending" @click="close">取消</button>
          <button class="confirm-command" type="submit" :disabled="pending">
            {{ pending ? '正在更新…' : '确认更新' }}
          </button>
        </footer>
      </form>

      <form v-else @submit.prevent="submitReset">
        <div class="dialog-subject">
          <strong>{{ user?.display_name }}</strong>
          <code>{{ user?.username }}</code>
        </div>
        <label>
          <span>新临时密码</span>
          <input
            v-model="resetForm.temporaryPassword"
            type="password"
            autocomplete="new-password"
            maxlength="1024"
            required
          >
          <small>提交后立即从浏览器表单清除，不会在页面回显。</small>
        </label>
        <p class="confirmation-note">
          确认后现有密码失效，账户下次登录必须修改临时密码。
        </p>
        <p v-if="formError || operationError" class="form-error" role="alert">
          {{ formError || operationError }}
        </p>
        <footer>
          <button type="button" :disabled="pending" @click="close">取消</button>
          <button class="danger-command" type="submit" :disabled="pending">
            {{ pending ? '正在重置…' : '确认重置' }}
          </button>
        </footer>
      </form>
    </section>
  </div>
</template>

<style scoped>
.dialog-backdrop {
  position: fixed;
  z-index: 80;
  display: grid;
  inset: 0;
  place-items: center;
  padding: 20px;
  background: rgb(23 36 39 / 48%);
}

.user-dialog {
  width: min(100%, 480px);
  max-height: calc(100vh - 40px);
  overflow-y: auto;
  border: 1px solid var(--line-strong);
  border-radius: 6px;
  background: var(--surface);
  box-shadow: 0 18px 46px rgb(23 36 39 / 24%);
}

.user-dialog > header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--line);
}

.dialog-kicker {
  display: block;
  margin-bottom: 5px;
  color: var(--teal-strong);
  font-size: 9px;
  font-weight: 700;
}

.user-dialog h3 {
  margin: 0;
  color: var(--ink-800);
  font-size: 14px;
}

.user-dialog header button {
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

.user-dialog form {
  display: grid;
  gap: 13px;
  padding: 16px;
}

.user-dialog label {
  display: grid;
  gap: 5px;
  color: var(--ink-600);
  font-size: 10px;
  font-weight: 700;
}

.user-dialog input,
.user-dialog select {
  width: 100%;
  min-height: 36px;
  padding: 6px 9px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-800);
  background: var(--surface);
  font-size: 11px;
}

.user-dialog label small {
  color: var(--ink-400);
  font-size: 9px;
  font-weight: 400;
}

.locked-edit-control {
  display: flex;
  align-items: center;
  gap: 7px;
  min-height: 32px;
  padding: 6px 8px;
  border: 1px solid #decba7;
  border-radius: 4px;
  color: var(--amber);
  background: #fff9ef;
  font-size: 9px;
  font-weight: 400;
}

.locked-edit-control input {
  width: 14px;
  min-height: 14px;
  flex: 0 0 14px;
  margin: 0;
}

.dialog-subject {
  padding: 10px;
  border-left: 3px solid var(--blue);
  color: var(--ink-600);
  background: #f2f6fa;
}

.dialog-subject strong,
.dialog-subject code {
  display: block;
}

.dialog-subject strong {
  color: var(--ink-800);
  font-size: 11px;
}

.dialog-subject code {
  margin-top: 3px;
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 9px;
}

.confirmation-note,
.form-error {
  margin: 0;
  padding: 9px 10px;
  border: 1px solid #decba7;
  border-radius: 4px;
  color: var(--ink-600);
  background: #fff9ef;
  font-size: 9px;
  line-height: 1.6;
}

.form-error {
  border-color: #e4bebe;
  color: var(--red);
  background: #fff5f5;
}

.user-dialog footer {
  display: flex;
  justify-content: flex-end;
  gap: 7px;
  padding-top: 3px;
}

.user-dialog footer button {
  min-height: 32px;
  padding: 5px 10px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
  font-size: 10px;
}

.user-dialog footer .confirm-command {
  border-color: var(--teal);
  color: #fff;
  background: var(--teal);
}

.user-dialog footer .danger-command {
  border-color: var(--red);
  color: #fff;
  background: var(--red);
}

.user-dialog button:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
</style>
