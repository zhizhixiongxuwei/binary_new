<script setup lang="ts">
import { onMounted } from 'vue'

import type {
  AuditLogListQuery,
  CreateAdminUserInput,
  ResetAdminUserPasswordInput,
  UpdateAdminUserInput,
} from '@/api/types'
import SystemStatusPanel from '@/components/system/SystemStatusPanel.vue'
import AnalyzerStatusPanel from '@/components/system/maintenance/AnalyzerStatusPanel.vue'
import AuditLogLivePanel from '@/components/system/maintenance/AuditLogLivePanel.vue'
import MaintenanceWorkspaceTabs from '@/components/system/maintenance/MaintenanceWorkspaceTabs.vue'
import OperationalMetricsPanel from '@/components/system/maintenance/OperationalMetricsPanel.vue'
import StorageStatusPanel from '@/components/system/maintenance/StorageStatusPanel.vue'
import UserManagementPanel from '@/components/system/maintenance/UserManagementPanel.vue'
import { useAdminUsers } from '@/composables/useAdminUsers'
import { useAuditLogs } from '@/composables/useAuditLogs'
import { useSystemMaintenance } from '@/composables/useSystemMaintenance'
import { useSessionStore } from '@/stores/session'

const session = useSessionStore()
const system = useSystemMaintenance()
const users = useAdminUsers()
const audit = useAuditLogs()

async function createUser(input: CreateAdminUserInput): Promise<void> {
  await users.create(input)
}

async function updateUser(
  userId: string,
  input: UpdateAdminUserInput,
): Promise<void> {
  await users.update(userId, input)
}

async function resetUserPassword(
  userId: string,
  input: ResetAdminUserPasswordInput,
): Promise<void> {
  await users.resetPassword(userId, input)
}

function searchAudit(query: AuditLogListQuery): void {
  void audit.load(query)
}

function refreshAudit(): void {
  void audit.load(audit.query.value)
}

onMounted(() => {
  void system.load()
  void users.load()
  void audit.load()
})
</script>

<template>
  <MaintenanceWorkspaceTabs>
    <template #runtime>
      <div class="runtime-workspace">
        <SystemStatusPanel
          managed
          :status="system.status.value"
          :loading="system.loading.value"
          :error-message="system.errorMessage.value"
          @retry="system.load"
        />
        <OperationalMetricsPanel
          v-if="system.status.value?.operational_metrics"
          :metrics="system.status.value.operational_metrics"
        />
      </div>
    </template>
    <template #storage>
      <StorageStatusPanel
        :status="system.status.value"
        :loading="system.loading.value"
        :error-message="system.errorMessage.value"
        @retry="system.load"
      />
    </template>
    <template #analyzers>
      <AnalyzerStatusPanel
        :status="system.status.value"
        :loading="system.loading.value"
        :error-message="system.errorMessage.value"
        @retry="system.load"
      />
    </template>
    <template #access>
      <UserManagementPanel
        :users="users.users.value"
        :loading="users.loading.value"
        :loading-more="users.loadingMore.value"
        :error-message="users.errorMessage.value"
        :operation-error="users.operationError.value"
        :pending-user-id="users.pendingUserId.value"
        :operation-succeeded-id="users.operationSucceededId.value"
        :has-more="Boolean(users.nextCursor.value)"
        :current-user-id="session.user?.id ?? ''"
        :current-role="session.user?.role ?? 'reader'"
        @retry="users.load"
        @search="users.search"
        @load-more="users.load({ append: true })"
        @create="createUser"
        @update="updateUser"
        @reset-password="resetUserPassword"
        @dismiss-operation-error="users.clearOperationError"
      />
    </template>
    <template #audit>
      <AuditLogLivePanel
        :logs="audit.logs.value"
        :loading="audit.loading.value"
        :loading-more="audit.loadingMore.value"
        :error-message="audit.errorMessage.value"
        :has-more="Boolean(audit.nextCursor.value)"
        @search="searchAudit"
        @retry="refreshAudit"
        @load-more="audit.load(audit.query.value, { append: true })"
      />
    </template>
  </MaintenanceWorkspaceTabs>
</template>

<style scoped>
.runtime-workspace {
  display: grid;
  min-width: 0;
  gap: 14px;
}
</style>
