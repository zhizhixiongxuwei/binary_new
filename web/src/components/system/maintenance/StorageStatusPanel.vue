<script setup lang="ts">
import { AlertTriangle, HardDrive, RefreshCw } from 'lucide-vue-next'
import { computed } from 'vue'

import type {
  StorageMountHealth,
  StorageMountStatus,
  SystemStatus,
} from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import { formatBytes, formatDateTime } from '@/utils/formatters'

const props = defineProps<{
  status: SystemStatus | null
  loading: boolean
  errorMessage: string
}>()

defineEmits<{
  retry: []
}>()

const mounts = computed(() => props.status?.storage_mounts ?? [])
const pressuredMounts = computed(() =>
  mounts.value.filter((mount) =>
    ['warning', 'critical', 'unavailable'].includes(healthFor(mount)),
  ),
)

function percent(used: number | null, total: number | null): number {
  if (used === null || total === null || total <= 0) return 0
  return Math.min(100, Math.max(0, Math.round((used / total) * 100)))
}

function healthFor(
  mount: StorageMountStatus,
): StorageMountHealth {
  if (mount.status) return mount.status
  if (mount.low_water) return 'critical'
  if (mount.writable === false) return 'unavailable'
  if (mount.total_bytes === null || mount.used_bytes === null) return 'unknown'
  const usage = percent(mount.used_bytes, mount.total_bytes)
  if (usage >= mount.critical_percent) return 'critical'
  if (usage >= mount.warning_percent) return 'warning'
  return 'healthy'
}

const healthLabels: Readonly<Record<StorageMountHealth, string>> = {
  healthy: '正常',
  warning: '接近水位',
  critical: '超过临界水位',
  unavailable: '不可用',
  unknown: '容量不可观测',
}
</script>

<template>
  <StatePanel v-if="loading" class="surface-panel" kind="loading" />
  <StatePanel
    v-else-if="errorMessage"
    class="surface-panel"
    kind="error"
    :description="errorMessage"
    retryable
    @retry="$emit('retry')"
  />
  <section
    v-else-if="status"
    class="storage-status surface-panel"
    aria-labelledby="storage-status-title"
  >
    <header class="section-heading">
      <div>
        <span class="section-kicker mono">LIVE / MOUNT TELEMETRY</span>
        <h2 id="storage-status-title">持久化目录与磁盘水位</h2>
        <p>路径来自部署配置和服务端文件系统检测，浏览器不会读取本机目录。</p>
      </div>
      <div class="heading-actions">
        <span class="checked-at mono">
          {{ formatDateTime(status.collected_at) }}
        </span>
        <button type="button" title="刷新存储状态" @click="$emit('retry')">
          <RefreshCw :size="15" aria-hidden="true" />
          <span>刷新</span>
        </button>
      </div>
    </header>

    <div v-if="pressuredMounts.length" class="pressure-alert" role="alert">
      <AlertTriangle :size="17" aria-hidden="true" />
      <span>
        <strong>{{ pressuredMounts.length }} 个目录需要处理</strong>
        <small>达到告警水位或不可写时，新任务可能被服务端暂停接收。</small>
      </span>
    </div>

    <ul
      v-if="status.diagnostics?.length"
      class="diagnostic-list"
      aria-label="系统存储诊断"
    >
      <li
        v-for="diagnostic in status.diagnostics"
        :key="`${diagnostic.code}-${diagnostic.component}`"
        :class="`diagnostic-item--${diagnostic.severity}`"
      >
        <span>
          <strong>{{ diagnostic.component }} · {{ diagnostic.code }}</strong>
          <small>{{ diagnostic.message }}</small>
        </span>
        <span>{{ diagnostic.remediation }}</span>
      </li>
    </ul>

    <StatePanel
      v-if="!mounts.length"
      kind="empty"
      title="服务端未返回挂载目录"
      description="请检查当前版本的 /admin/system 响应和部署目录配置。"
    />
    <div v-else class="mount-table" role="table" aria-label="持久化目录容量">
      <div class="mount-table__header" role="row">
        <span role="columnheader">目录</span>
        <span role="columnheader">主机 / 容器映射</span>
        <span role="columnheader">服务</span>
        <span role="columnheader">容量水位</span>
      </div>
      <div
        v-for="mount in mounts"
        :key="mount.id"
        class="mount-row"
        role="row"
      >
        <div class="mount-identity" role="cell" data-label="目录">
          <span class="mount-icon" aria-hidden="true">
            <HardDrive :size="16" />
          </span>
          <span>
            <strong>{{ mount.label }}</strong>
            <small>{{ mount.purpose }}</small>
          </span>
        </div>
        <div class="path-pair" role="cell" data-label="主机 / 容器映射">
          <code>{{ mount.host_path || '未由 API 容器挂载' }}</code>
          <code>{{ mount.container_path }}</code>
        </div>
        <div class="service-list" role="cell" data-label="服务">
          <span v-for="service in mount.services" :key="service">{{ service }}</span>
        </div>
        <div class="usage-cell" role="cell" data-label="容量水位">
          <div class="usage-meta">
            <span class="mono">
              {{ formatBytes(mount.used_bytes ?? undefined) }} /
              {{ formatBytes(mount.total_bytes ?? undefined) }}
            </span>
            <span
              class="health-label"
              :class="`health-label--${healthFor(mount)}`"
            >
              {{ healthLabels[healthFor(mount)] }}
            </span>
          </div>
          <div
            class="usage-meter"
            :class="`usage-meter--${healthFor(mount)}`"
            role="progressbar"
            :aria-label="`${mount.label} 使用率`"
            aria-valuemin="0"
            aria-valuemax="100"
            :aria-valuenow="percent(mount.used_bytes, mount.total_bytes)"
          >
            <span
              :style="{
                width: `${percent(mount.used_bytes, mount.total_bytes)}%`,
              }"
            />
          </div>
          <small class="watermarks mono">
            WARN {{ mount.warning_percent }}% / CRIT {{ mount.critical_percent }}%
          </small>
          <small
            v-if="
              mount.free_bytes !== undefined ||
                mount.minimum_free_bytes !== undefined
            "
            class="watermarks mono"
          >
            FREE {{ formatBytes(mount.free_bytes ?? undefined) }} / MIN
            {{ formatBytes(mount.minimum_free_bytes ?? undefined) }}
          </small>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.storage-status {
  min-width: 0;
  overflow: hidden;
  container: storage-live / inline-size;
}

.section-heading {
  display: flex;
  min-height: 76px;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
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
  align-items: center;
  gap: 10px;
}

.checked-at {
  color: var(--ink-400);
  font-size: 9px;
}

.heading-actions button {
  display: inline-flex;
  min-height: 32px;
  align-items: center;
  gap: 6px;
  padding: 5px 9px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
  font-size: 10px;
}

.pressure-alert {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 17px;
  border-bottom: 1px solid #decba7;
  color: var(--amber);
  background: #fff9ef;
}

.pressure-alert > svg {
  flex: 0 0 auto;
}

.pressure-alert span,
.pressure-alert strong,
.pressure-alert small {
  display: block;
}

.diagnostic-list {
  padding: 0;
  margin: 0;
  list-style: none;
}

.diagnostic-list li {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(200px, 0.9fr) minmax(240px, 1.1fr);
  align-items: center;
  gap: 14px;
  padding: 9px 17px;
  border-bottom: 1px solid #decba7;
  color: var(--ink-600);
  background: #fffdf8;
  font-size: 9px;
}

.diagnostic-list li.diagnostic-item--error {
  border-color: #e4bebe;
  background: #fff8f8;
}

.diagnostic-list strong,
.diagnostic-list small {
  display: block;
}

.diagnostic-list strong {
  color: var(--ink-800);
  font-size: 9px;
}

.diagnostic-list small {
  margin-top: 2px;
  color: var(--ink-600);
  font-size: 8px;
}

.pressure-alert strong {
  font-size: 10px;
}

.pressure-alert small {
  margin-top: 2px;
  color: var(--ink-600);
  font-size: 9px;
}

.mount-table__header,
.mount-row {
  display: grid;
  min-width: 0;
  grid-template-columns:
    minmax(170px, 0.75fr) minmax(260px, 1.35fr)
    minmax(110px, 0.55fr) minmax(210px, 1fr);
  align-items: center;
  gap: 15px;
  padding: 11px 17px;
}

.mount-table__header {
  color: var(--ink-600);
  background: #f7f9f9;
  font-size: 9px;
  font-weight: 700;
}

.mount-row {
  min-height: 82px;
  border-top: 1px solid #e7ebeb;
}

.mount-identity {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 9px;
}

.mount-icon {
  display: grid;
  width: 32px;
  height: 32px;
  flex: 0 0 32px;
  place-items: center;
  border: 1px solid #c0d1e4;
  border-radius: 4px;
  color: var(--blue);
  background: #f2f6fa;
}

.mount-identity strong,
.mount-identity small {
  display: block;
  overflow-wrap: anywhere;
}

.mount-identity strong {
  color: var(--ink-800);
  font-size: 11px;
}

.mount-identity small {
  margin-top: 3px;
  color: var(--ink-600);
  font-size: 9px;
}

.path-pair {
  display: grid;
  min-width: 0;
  gap: 5px;
}

.path-pair code {
  color: var(--ink-600);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 9px;
  overflow-wrap: anywhere;
}

.service-list {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.service-list span {
  padding: 2px 5px;
  border: 1px solid var(--line);
  border-radius: 3px;
  color: var(--ink-600);
  background: #f7f9f9;
  font-size: 9px;
}

.usage-meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  color: var(--ink-600);
  font-size: 9px;
}

.health-label {
  color: var(--teal-strong);
  font-weight: 700;
  white-space: nowrap;
}

.health-label--warning {
  color: var(--amber);
}

.health-label--critical,
.health-label--unavailable {
  color: var(--red);
}

.health-label--unknown {
  color: var(--ink-400);
}

.usage-meter {
  height: 5px;
  margin-top: 8px;
  overflow: hidden;
  border-radius: 2px;
  background: #e6eaeb;
}

.usage-meter span {
  display: block;
  height: 100%;
  background: var(--teal);
}

.usage-meter--warning span {
  background: var(--amber);
}

.usage-meter--critical span,
.usage-meter--unavailable span {
  background: var(--red);
}

.usage-meter--unknown span {
  background: var(--ink-400);
}

.watermarks {
  display: block;
  margin-top: 5px;
  color: var(--ink-400);
  font-size: 8px;
}

@container storage-live (max-width: 900px) {
  .mount-table__header {
    display: none;
  }

  .mount-row {
    grid-template-columns: minmax(180px, 0.8fr) minmax(0, 1.2fr);
  }

  .mount-row > [role="cell"]::before {
    display: block;
    margin-bottom: 5px;
    color: var(--ink-400);
    content: attr(data-label);
    font-size: 8px;
  }

  .mount-identity::before {
    display: none !important;
  }
}

@container storage-live (max-width: 560px) {
  .section-heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .heading-actions {
    width: 100%;
    justify-content: space-between;
  }

  .mount-row {
    grid-template-columns: 1fr;
    padding: 14px;
  }

  .diagnostic-list li {
    grid-template-columns: 1fr;
  }
}
</style>
