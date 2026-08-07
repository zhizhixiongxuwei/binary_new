<script setup lang="ts">
import { Activity, Clock3, Database, HardDrive, Server, Wrench } from 'lucide-vue-next'
import { computed, onMounted, shallowRef } from 'vue'

import { api, ApiError } from '@/api/client'
import type { SystemStatus } from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import { formatBytes, formatDateTime } from '@/utils/formatters'

const props = withDefaults(
  defineProps<{
    status?: SystemStatus | null
    loading?: boolean
    errorMessage?: string
    managed?: boolean
  }>(),
  {
    status: null,
    loading: false,
    errorMessage: '',
    managed: false,
  },
)

const emit = defineEmits<{
  retry: []
}>()

const localStatus = shallowRef<SystemStatus | null>(null)
const localLoading = shallowRef(true)
const localErrorMessage = shallowRef('')
const visibleStatus = computed(() =>
  props.managed ? props.status : localStatus.value,
)
const visibleLoading = computed(() =>
  props.managed ? props.loading : localLoading.value,
)
const visibleErrorMessage = computed(() =>
  props.managed ? props.errorMessage : localErrorMessage.value,
)

const serviceLabel = computed(() => {
  const labels = {
    healthy: '运行正常',
    degraded: '部分降级',
    unavailable: '不可用',
  } as const
  return visibleStatus.value ? labels[visibleStatus.value.service_status] : '未知'
})

const repositoryPercent = computed(() => {
  const total = visibleStatus.value?.repository_total_bytes ?? 0
  const used = visibleStatus.value?.repository_used_bytes ?? 0
  if (total <= 0 || used <= 0) return 0
  return Math.min(100, Math.max(0, Math.round((used / total) * 100)))
})

const taskCountEntries = computed(() =>
  Object.entries(visibleStatus.value?.task_counts ?? {}).sort(([left], [right]) =>
    left.localeCompare(right),
  ),
)

const leaseKindEntries = computed(() =>
  Object.entries(
    visibleStatus.value?.worker_summary?.leases_by_kind ?? {},
  ).sort(([left], [right]) => left.localeCompare(right)),
)

function analyzerStatusLabel(value: 'available' | 'unavailable'): string {
  return value === 'available' ? '可用' : '不可用'
}

async function load(): Promise<void> {
  localLoading.value = true
  localErrorMessage.value = ''
  try {
    localStatus.value = await api.getSystemStatus()
  } catch (error) {
    localErrorMessage.value =
      error instanceof ApiError ? error.message : '系统状态读取失败'
  } finally {
    localLoading.value = false
  }
}

function retry(): void {
  if (props.managed) {
    emit('retry')
    return
  }
  void load()
}

onMounted(() => {
  if (!props.managed) void load()
})
</script>

<template>
  <StatePanel v-if="visibleLoading" class="surface-panel" kind="loading" />
  <StatePanel
    v-else-if="visibleErrorMessage"
    class="surface-panel"
    kind="error"
    :description="visibleErrorMessage"
    retryable
    @retry="retry"
  />
  <div v-else-if="visibleStatus" class="system-status">
    <dl class="system-summary surface-panel" aria-label="系统运行摘要">
      <div class="summary-item">
        <span class="summary-icon summary-icon--teal">
          <Server :size="18" aria-hidden="true" />
        </span>
        <div>
          <dt>服务状态</dt>
          <dd
            class="service-value"
            :class="`service-value--${visibleStatus.service_status}`"
          >
            <i aria-hidden="true" />
            {{ serviceLabel }}
          </dd>
        </div>
      </div>
      <div class="summary-item">
        <span class="summary-icon summary-icon--blue">
          <Wrench :size="18" aria-hidden="true" />
        </span>
        <div>
          <dt>平台版本</dt>
          <dd class="mono">
            {{ visibleStatus.build?.version || visibleStatus.version || '未提供' }}
          </dd>
          <small v-if="visibleStatus.build" class="summary-detail mono">
            {{ visibleStatus.build.commit || 'unknown commit' }} /
            {{ visibleStatus.build.go_version || 'unknown go' }}
          </small>
        </div>
      </div>
      <div class="summary-item">
        <span class="summary-icon summary-icon--amber">
          <HardDrive :size="18" aria-hidden="true" />
        </span>
        <div>
          <dt>仓库使用</dt>
          <dd class="mono">
            {{ formatBytes(visibleStatus.repository_used_bytes) }} /
            {{ formatBytes(visibleStatus.repository_total_bytes) }}
          </dd>
          <div
            class="repository-meter"
            role="progressbar"
            aria-label="仓库存储使用率"
            aria-valuemin="0"
            aria-valuemax="100"
            :aria-valuenow="repositoryPercent"
          >
            <span :style="{ width: `${repositoryPercent}%` }" />
          </div>
        </div>
      </div>
      <div class="summary-item">
        <span class="summary-icon">
          <Database :size="18" aria-hidden="true" />
        </span>
        <div>
          <dt>Trivy DB</dt>
          <dd class="mono">{{ visibleStatus.trivy_db_version || '未导入' }}</dd>
        </div>
      </div>
      <div class="summary-item">
        <span class="summary-icon summary-icon--blue">
          <Activity :size="18" aria-hidden="true" />
        </span>
        <div>
          <dt>活动任务</dt>
          <dd class="mono">{{ visibleStatus.active_tasks }}</dd>
        </div>
      </div>
      <div class="summary-item">
        <span class="summary-icon">
          <Clock3 :size="18" aria-hidden="true" />
        </span>
        <div>
          <dt>队列深度</dt>
          <dd class="mono">
            {{ visibleStatus.queue_depth ?? visibleStatus.queued_tasks }}
          </dd>
        </div>
      </div>
    </dl>

    <section
      v-if="taskCountEntries.length || visibleStatus.worker_summary || visibleStatus.build"
      class="runtime-observations surface-panel"
      aria-label="任务与租约观测"
    >
      <div class="runtime-block">
        <header>
          <div>
            <h2>全局任务状态</h2>
            <p>服务端当前数据库计数，不是最近任务抽样。</p>
          </div>
          <span class="mono">{{ taskCountEntries.length }} STATES</span>
        </header>
        <StatePanel
          v-if="!taskCountEntries.length"
          kind="empty"
          title="未提供全局任务计数"
        />
        <dl v-else class="task-counts">
          <div v-for="[name, count] in taskCountEntries" :key="name">
            <dt class="mono">{{ name }}</dt>
            <dd class="mono">{{ count }}</dd>
          </div>
        </dl>
      </div>

      <div class="runtime-block runtime-block--leases">
        <header>
          <div>
            <h2>Worker 租约观测</h2>
            <p>仅表示数据库中观察到的有效租约与心跳，不是进程在线清单。</p>
          </div>
          <span class="mono">
            {{ visibleStatus.worker_summary?.observed_leases ?? 0 }} LEASES
          </span>
        </header>
        <div v-if="visibleStatus.worker_summary" class="lease-summary">
          <dl>
            <div>
              <dt>有效租约</dt>
              <dd class="mono">
                {{ visibleStatus.worker_summary.observed_leases }}
              </dd>
            </div>
            <div>
              <dt>观察到的 owner</dt>
              <dd class="mono">
                {{ visibleStatus.worker_summary.observed_owners }}
              </dd>
            </div>
            <div>
              <dt>最早心跳</dt>
              <dd class="mono">
                {{
                  formatDateTime(
                    visibleStatus.worker_summary.oldest_heartbeat_at ?? undefined,
                  )
                }}
              </dd>
            </div>
            <div>
              <dt>最近心跳</dt>
              <dd class="mono">
                {{
                  formatDateTime(
                    visibleStatus.worker_summary.latest_heartbeat_at ?? undefined,
                  )
                }}
              </dd>
            </div>
          </dl>
          <div class="lease-kinds" aria-label="按类型统计的有效租约">
            <span v-for="[kind, count] in leaseKindEntries" :key="kind">
              <code>{{ kind }}</code>
              <strong class="mono">{{ count }}</strong>
            </span>
          </div>
        </div>
        <StatePanel v-else kind="empty" title="未提供 Worker 租约观测" />
      </div>

      <footer v-if="visibleStatus.build" class="build-footnote">
        <span>构建时间 {{ formatDateTime(visibleStatus.build.build_time) }}</span>
        <code>{{ visibleStatus.build.commit || 'unknown' }}</code>
      </footer>
    </section>

    <section class="analyzers surface-panel">
      <header>
        <h2>分析器状态</h2>
        <span class="mono">{{ visibleStatus.analyzers?.length ?? 0 }} 个分析器</span>
      </header>
      <StatePanel
        v-if="!visibleStatus.analyzers?.length"
        kind="empty"
        title="暂无分析器信息"
      />
      <div v-else class="analyzer-table">
        <table>
          <caption class="sr-only">分析器名称、版本和可用状态</caption>
          <thead>
            <tr>
              <th scope="col">分析器</th>
              <th scope="col">版本</th>
              <th scope="col">状态</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="analyzer in visibleStatus.analyzers" :key="analyzer.name">
              <td><strong>{{ analyzer.name }}</strong></td>
              <td class="mono">{{ analyzer.version }}</td>
              <td>
                <span
                  class="analyzer-state"
                  :class="`analyzer-state--${analyzer.status}`"
                >
                  <i aria-hidden="true" />
                  {{ analyzerStatusLabel(analyzer.status) }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<style scoped>
.system-status {
  display: grid;
  gap: 16px;
  container: system-status / inline-size;
}

.system-summary {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  padding: 0;
  margin: 0;
}

.summary-item {
  display: flex;
  min-width: 0;
  min-height: 94px;
  align-items: center;
  gap: 13px;
  padding: 16px 18px;
  border-right: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
}

.summary-item:nth-child(3n) {
  border-right: 0;
}

.summary-item:nth-last-child(-n + 3) {
  border-bottom: 0;
}

.summary-icon {
  display: grid;
  width: 36px;
  height: 36px;
  flex: 0 0 36px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: 5px;
  color: var(--ink-600);
  background: var(--surface-raised);
}

.summary-icon--teal {
  border-color: #bdd5d2;
  color: var(--teal);
  background: #f1f8f7;
}

.summary-icon--blue {
  border-color: #c0d1e4;
  color: var(--blue);
  background: #f2f6fa;
}

.summary-icon--amber {
  border-color: #decba7;
  color: var(--amber);
  background: #fff9ef;
}

.summary-item > div {
  min-width: 0;
  flex: 1;
}

.summary-item dt,
.summary-item dd {
  margin: 0;
}

.summary-detail {
  display: block;
  margin-top: 4px;
  color: var(--ink-400);
  font-size: 8px;
  overflow-wrap: anywhere;
}

.summary-item dt {
  color: var(--ink-600);
  font-size: 10px;
}

.summary-item dd {
  margin-top: 6px;
  color: var(--ink-800);
  font-size: 13px;
  font-weight: 700;
  overflow-wrap: anywhere;
}

.service-value {
  display: flex;
  align-items: center;
  gap: 7px;
}

.service-value i {
  width: 7px;
  height: 7px;
  flex: 0 0 7px;
  border-radius: 50%;
  background: var(--ink-400);
}

.service-value--healthy {
  color: var(--teal-strong) !important;
}

.service-value--healthy i {
  background: var(--teal);
}

.service-value--degraded {
  color: var(--amber) !important;
}

.service-value--degraded i {
  background: var(--amber);
}

.service-value--unavailable {
  color: var(--red) !important;
}

.service-value--unavailable i {
  background: var(--red);
}

.repository-meter {
  height: 4px;
  margin-top: 8px;
  overflow: hidden;
  border-radius: 2px;
  background: #e6eaeb;
}

.repository-meter span {
  display: block;
  height: 100%;
  background: var(--amber);
}

.runtime-observations {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(0, 0.9fr) minmax(0, 1.1fr);
  overflow: hidden;
}

.runtime-block {
  min-width: 0;
  border-right: 1px solid var(--line);
}

.runtime-block--leases {
  border-right: 0;
}

.runtime-block > header {
  display: flex;
  min-height: 62px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 11px 16px;
  border-bottom: 1px solid var(--line);
}

.runtime-block h2,
.runtime-block p {
  margin: 0;
}

.runtime-block h2 {
  color: var(--ink-800);
  font-size: 12px;
}

.runtime-block p {
  margin-top: 3px;
  color: var(--ink-600);
  font-size: 8px;
  line-height: 1.5;
}

.runtime-block header > span {
  flex: 0 0 auto;
  color: var(--ink-400);
  font-size: 8px;
}

.task-counts {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  padding: 0;
  margin: 0;
}

.task-counts > div {
  display: flex;
  min-width: 0;
  min-height: 48px;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 8px 12px;
  border-right: 1px solid #e7ebeb;
  border-bottom: 1px solid #e7ebeb;
}

.task-counts dt,
.task-counts dd {
  margin: 0;
}

.task-counts dt {
  min-width: 0;
  color: var(--ink-600);
  font-size: 8px;
  overflow-wrap: anywhere;
}

.task-counts dd {
  color: var(--ink-800);
  font-size: 12px;
  font-weight: 700;
}

.lease-summary {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(0, 1fr) minmax(130px, 0.55fr);
}

.lease-summary > dl {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  padding: 0;
  margin: 0;
}

.lease-summary > dl > div {
  min-width: 0;
  min-height: 54px;
  padding: 9px 12px;
  border-right: 1px solid #e7ebeb;
  border-bottom: 1px solid #e7ebeb;
}

.lease-summary dt,
.lease-summary dd {
  margin: 0;
}

.lease-summary dt {
  color: var(--ink-400);
  font-size: 8px;
}

.lease-summary dd {
  margin-top: 5px;
  color: var(--ink-800);
  font-size: 10px;
  overflow-wrap: anywhere;
}

.lease-kinds {
  display: grid;
  align-content: start;
  gap: 6px;
  padding: 10px;
  background: #f7f9f9;
}

.lease-kinds span {
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 5px 7px;
  border: 1px solid var(--line);
  border-radius: 3px;
  background: var(--surface);
}

.lease-kinds code,
.lease-kinds strong {
  color: var(--ink-600);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 8px;
  overflow-wrap: anywhere;
}

.lease-kinds strong {
  color: var(--ink-800);
}

.build-footnote {
  display: flex;
  min-height: 34px;
  grid-column: 1 / -1;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 6px 16px;
  border-top: 1px solid var(--line);
  color: var(--ink-400);
  background: #f7f9f9;
  font-size: 8px;
}

.build-footnote code {
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  overflow-wrap: anywhere;
}

.analyzers header {
  display: flex;
  min-height: 50px;
  align-items: center;
  justify-content: space-between;
  padding: 0 17px;
  border-bottom: 1px solid var(--line);
}

.analyzers h2 {
  margin: 0;
  color: var(--ink-800);
  font-size: 13px;
}

.analyzers header span {
  color: var(--ink-400);
  font-size: 10px;
  white-space: nowrap;
}

.analyzer-table {
  min-width: 0;
  overflow-x: auto;
}

.analyzer-table table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
}

.analyzer-table th,
.analyzer-table td {
  padding: 10px 17px;
  border-bottom: 1px solid #e8ebec;
  text-align: left;
  vertical-align: middle;
  overflow-wrap: anywhere;
}

.analyzer-table th {
  color: var(--ink-600);
  background: #f7f9f9;
  font-size: 10px;
  font-weight: 700;
}

.analyzer-table th:first-child {
  width: 40%;
}

.analyzer-table th:nth-child(2) {
  width: 36%;
}

.analyzer-table th:last-child {
  width: 24%;
}

.analyzer-table tbody tr:last-child td {
  border-bottom: 0;
}

.analyzer-table strong {
  color: var(--ink-800);
  font-size: 12px;
}

.analyzer-table td {
  color: var(--ink-600);
  font-size: 11px;
}

.analyzer-state {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.analyzer-state i {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--red);
}

.analyzer-state--available i {
  background: var(--teal);
}

@container system-status (max-width: 900px) {
  .system-summary {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .system-summary > .summary-item {
    border-right: 1px solid var(--line);
    border-bottom: 1px solid var(--line);
  }

  .summary-item:nth-child(2n) {
    border-right: 0;
  }

  .summary-item:nth-last-child(-n + 2) {
    border-bottom: 0;
  }

  .runtime-observations {
    grid-template-columns: 1fr;
  }

  .runtime-block {
    border-right: 0;
    border-bottom: 1px solid var(--line);
  }
}

@container system-status (max-width: 540px) {
  .system-summary {
    grid-template-columns: 1fr;
  }

  .summary-item {
    min-height: 78px;
    padding: 14px;
    border-right: 0 !important;
    border-bottom: 1px solid var(--line) !important;
  }

  .summary-item:last-child {
    border-bottom: 0 !important;
  }

  .task-counts {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .lease-summary {
    grid-template-columns: 1fr;
  }

  .runtime-block > header {
    align-items: flex-start;
    flex-direction: column;
  }

  .analyzers header {
    padding: 0 13px;
  }

  .analyzer-table th,
  .analyzer-table td {
    padding-right: 10px;
    padding-left: 10px;
  }

  .analyzer-table th:first-child {
    width: 42%;
  }

  .analyzer-table th:nth-child(2) {
    width: 33%;
  }

  .analyzer-table th:last-child {
    width: 25%;
  }
}
</style>
