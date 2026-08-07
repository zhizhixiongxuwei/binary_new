<script setup lang="ts">
import { Box, Database, FolderClock, HardDrive, ScrollText } from 'lucide-vue-next'
import { computed, type Component } from 'vue'

import MaintenanceUnavailable from '@/components/system/maintenance/MaintenanceUnavailable.vue'
import {
  mountPathPreviews,
  type MaintenanceViewMode,
  type MountPathPreview,
} from '@/components/system/maintenance/maintenanceFixtures'
import { formatBytes } from '@/utils/formatters'

defineProps<{
  mode: MaintenanceViewMode
}>()

const iconByPath: Readonly<Record<string, Component>> = {
  repository: Box,
  uploads: HardDrive,
  'task-work': FolderClock,
  logs: ScrollText,
  mysql: Database,
}

const rows = computed(() =>
  mountPathPreviews.map((path) => ({
    ...path,
    percent: usagePercent(path),
    icon: iconByPath[path.id] ?? HardDrive,
  })),
)

function usagePercent(path: MountPathPreview): number {
  if (path.totalBytes <= 0) return 0
  return Math.min(100, Math.max(0, Math.round((path.usedBytes / path.totalBytes) * 100)))
}
</script>

<template>
  <MaintenanceUnavailable
    v-if="mode === 'live'"
    title="存储维护接口未接入"
    description="后端尚未提供挂载目录容量和运行时路径接口，本页不会读取本机文件系统。"
  />

  <section v-else class="storage-panel surface-panel" aria-labelledby="storage-title">
    <header class="maintenance-section-header">
      <div>
        <span class="preview-kicker mono">FIXED PREVIEW / DEPLOYMENT DEFAULTS</span>
        <h2 id="storage-title">持久化挂载目录</h2>
        <p>固定示例采用默认安装根目录 <code>/opt/binaryscan</code>，不是当前主机实测值。</p>
      </div>
      <span class="preview-badge">固定示例</span>
    </header>

    <div class="mount-list">
      <article v-for="row in rows" :key="row.id" class="mount-row">
        <div class="mount-row__identity">
          <span class="mount-row__icon" aria-hidden="true">
            <component :is="row.icon" :size="17" />
          </span>
          <div>
            <h3>{{ row.label }}</h3>
            <p>{{ row.purpose }}</p>
          </div>
        </div>

        <dl class="mount-row__paths">
          <div>
            <dt>宿主机</dt>
            <dd><code>{{ row.hostPath }}</code></dd>
          </div>
          <div>
            <dt>容器内</dt>
            <dd>
              <code>{{ row.containerPath }}</code>
              <ul v-if="row.serviceMappings" class="service-mappings">
                <li v-for="mapping in row.serviceMappings" :key="mapping">
                  <code>{{ mapping }}</code>
                </li>
              </ul>
            </dd>
          </div>
          <div>
            <dt>使用服务</dt>
            <dd class="mono">{{ row.services }}</dd>
          </div>
        </dl>

        <div class="mount-row__usage">
          <div class="usage-copy">
            <span>示例用量</span>
            <strong class="mono">
              {{ formatBytes(row.usedBytes) }} / {{ formatBytes(row.totalBytes) }}
            </strong>
          </div>
          <div
            class="usage-meter"
            role="progressbar"
            :aria-label="`${row.label} 示例存储使用率`"
            aria-valuemin="0"
            aria-valuemax="100"
            :aria-valuenow="row.percent"
          >
            <span :style="{ width: `${row.percent}%` }" />
          </div>
        </div>
      </article>
    </div>
  </section>
</template>

<style scoped>
.storage-panel {
  min-width: 0;
  container: storage-panel / inline-size;
}

.maintenance-section-header {
  display: flex;
  min-height: 86px;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18px;
  padding: 16px 18px;
  border-bottom: 1px solid var(--line);
}

.maintenance-section-header > div {
  min-width: 0;
}

.preview-kicker {
  display: block;
  margin-bottom: 6px;
  color: var(--teal-strong);
  font-size: 9px;
  font-weight: 700;
}

.maintenance-section-header h2 {
  margin: 0;
  color: var(--ink-800);
  font-size: 14px;
}

.maintenance-section-header p {
  margin: 5px 0 0;
  color: var(--ink-600);
  font-size: 11px;
  line-height: 1.6;
  overflow-wrap: anywhere;
}

.maintenance-section-header code,
.mount-row code {
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
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

.mount-list {
  display: grid;
}

.mount-row {
  display: grid;
  min-width: 0;
  grid-template-columns:
    minmax(170px, 0.8fr)
    minmax(280px, 1.7fr)
    minmax(170px, 0.8fr);
  align-items: center;
  gap: 18px;
  padding: 15px 18px;
  border-bottom: 1px solid #e7ebeb;
}

.mount-row:last-child {
  border-bottom: 0;
}

.mount-row__identity {
  display: flex;
  min-width: 0;
  align-items: flex-start;
  gap: 10px;
}

.mount-row__icon {
  display: grid;
  width: 32px;
  height: 32px;
  flex: 0 0 32px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--blue);
  background: #f3f7fa;
}

.mount-row__identity > div {
  min-width: 0;
}

.mount-row h3,
.mount-row p {
  margin: 0;
}

.mount-row h3 {
  color: var(--ink-800);
  font-size: 12px;
}

.mount-row p {
  margin-top: 4px;
  color: var(--ink-600);
  font-size: 10px;
  line-height: 1.5;
}

.mount-row__paths {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(0, 1.25fr) minmax(0, 0.8fr) minmax(0, 0.6fr);
  gap: 12px;
  margin: 0;
}

.mount-row__paths div {
  min-width: 0;
}

.mount-row__paths dt,
.mount-row__paths dd {
  margin: 0;
}

.service-mappings {
  display: grid;
  gap: 2px;
  padding: 0;
  margin: 4px 0 0;
  color: var(--ink-600);
  list-style: none;
}

.service-mappings code {
  font-size: 9px;
}

.mount-row__paths dt {
  color: var(--ink-400);
  font-size: 9px;
}

.mount-row__paths dd {
  margin-top: 4px;
  color: var(--ink-800);
  font-size: 10px;
  line-height: 1.5;
  overflow-wrap: anywhere;
}

.mount-row__usage {
  min-width: 0;
}

.usage-copy {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  color: var(--ink-400);
  font-size: 9px;
}

.usage-copy strong {
  min-width: 0;
  color: var(--ink-600);
  font-size: 9px;
  overflow-wrap: anywhere;
  text-align: right;
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

@container storage-panel (max-width: 980px) {
  .mount-row {
    grid-template-columns: minmax(160px, 0.7fr) minmax(0, 1.3fr);
  }

  .mount-row__usage {
    grid-column: 1 / -1;
  }
}

@container storage-panel (max-width: 620px) {
  .mount-row {
    grid-template-columns: 1fr;
    gap: 13px;
    padding: 15px 14px;
  }

  .mount-row__paths {
    grid-template-columns: 1fr;
    gap: 8px;
  }

  .mount-row__usage {
    grid-column: auto;
  }

  .maintenance-section-header {
    min-height: 0;
    flex-direction: column;
    gap: 10px;
    padding: 14px;
  }
}
</style>
