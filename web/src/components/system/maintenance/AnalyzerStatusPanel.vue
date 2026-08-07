<script setup lang="ts">
import {
  ArchiveRestore,
  DatabaseZap,
  RefreshCw,
} from 'lucide-vue-next'
import { computed } from 'vue'

import type {
  DatabaseBundleHealth,
  SystemStatus,
} from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import { formatDateTime } from '@/utils/formatters'

const props = defineProps<{
  status: SystemStatus | null
  loading: boolean
  errorMessage: string
}>()

defineEmits<{
  retry: []
}>()

const analyzers = computed(() => props.status?.analyzers ?? [])
const bundle = computed(() => props.status?.trivy_database_bundle ?? null)
const bundleIsStale = computed(
  () =>
    bundle.value?.status === 'stale' ||
    (bundle.value !== null &&
      bundle.value.age_days > bundle.value.stale_after_days),
)

const databaseStatusLabels: Readonly<Record<DatabaseBundleHealth, string>> = {
  active: '使用中',
  stale: '已过旧',
}

type AnalyzerStatus = NonNullable<SystemStatus['analyzers']>[number]

function analyzerStatusLabel(status: 'available' | 'unavailable'): string {
  return status === 'available' ? '可用' : '不可用'
}

function workerKindIsReady(
  analyzer: AnalyzerStatus,
  kind: 'image' | 'native' | 'trivy',
): boolean {
  return analyzer.ready_worker_kinds.includes(kind)
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
  <div v-else-if="status" class="analyzer-status">
    <section
      class="analyzer-section surface-panel"
      aria-labelledby="live-analyzer-title"
    >
      <header class="section-heading">
        <div>
          <span class="section-kicker mono">LIVE / TOOLCHAIN</span>
          <h2 id="live-analyzer-title">分析器可用性</h2>
          <p>版本和探测结果由离线节点返回，不会从互联网检查更新。</p>
        </div>
        <button type="button" title="刷新分析器状态" @click="$emit('retry')">
          <RefreshCw :size="15" aria-hidden="true" />
          <span>刷新</span>
        </button>
      </header>

      <StatePanel
        v-if="!analyzers.length"
        kind="empty"
        title="服务端未返回分析器状态"
      />
      <div v-else class="analyzer-grid">
        <article
          v-for="analyzer in analyzers"
          :key="analyzer.name"
          class="analyzer-row"
        >
          <span class="analyzer-icon" aria-hidden="true">
            <DatabaseZap :size="17" />
          </span>
          <div class="analyzer-identity">
            <strong>{{ analyzer.name }}</strong>
            <span>{{ analyzer.scope || analyzer.detail || '未提供检测范围' }}</span>
          </div>
          <div class="analyzer-version">
            <code>{{ analyzer.version || '未探测' }}</code>
            <small>期望 {{ analyzer.expected_version || '未配置' }}</small>
          </div>
          <span
            class="state-label"
            :class="`state-label--${analyzer.status}`"
          >
            <i aria-hidden="true" />
            {{ analyzerStatusLabel(analyzer.status) }}
          </span>
          <div class="analyzer-readiness">
            <div class="worker-kinds" aria-label="分析器 Worker 就绪状态">
              <span
                v-for="kind in analyzer.required_worker_kinds"
                :key="kind"
                :class="{
                  'worker-kind--ready': workerKindIsReady(analyzer, kind),
                }"
              >
                <i aria-hidden="true" />
                {{ kind }}
              </span>
              <small>{{ analyzer.ready_workers }} READY</small>
            </div>
            <code v-if="analyzer.runtime_version" class="runtime-version">
              {{ analyzer.runtime_name }} / {{ analyzer.runtime_version }}
            </code>
            <p>{{ analyzer.detail || '服务端未提供就绪详情。' }}</p>
            <div class="analyzer-times">
              <span>
                探测 {{ formatDateTime(analyzer.last_checked_at ?? undefined) }}
              </span>
              <span>
                最近运行 {{ formatDateTime(analyzer.last_run_at ?? undefined) }}
              </span>
            </div>
          </div>
        </article>
      </div>
    </section>

    <section
      class="database-section surface-panel"
      aria-labelledby="live-database-title"
    >
      <header class="section-heading">
        <div>
          <span class="section-kicker mono">LIVE / FIXED DATABASE BUNDLE</span>
          <h2 id="live-database-title">Trivy 数据库 Bundle</h2>
          <p>主漏洞库和 Java 漏洞库随扫描镜像固定交付，运行时不会联网更新。</p>
        </div>
        <span class="database-count mono">{{ bundle ? '1 BUNDLE' : 'NOT READY' }}</span>
      </header>

      <div v-if="bundleIsStale" class="stale-alert" role="alert">
        <ArchiveRestore :size="17" aria-hidden="true" />
        <span>
          <strong>数据库 Bundle 需要更新</strong>
          <small>请替换包含新双库 Bundle 的 scanner 镜像。</small>
        </span>
      </div>

      <StatePanel
        v-if="!bundle"
        kind="empty"
        title="Scanner 尚未登记数据库 Bundle"
        description="启动 scanner 服务后会登记镜像内的固定双库身份。"
      />
      <div v-else class="database-table" role="table" aria-label="Trivy 数据库 Bundle 状态">
        <div class="database-table__header" role="row">
          <span role="columnheader">Bundle</span>
          <span role="columnheader">主库 / Java 库</span>
          <span role="columnheader">登记时间</span>
          <span role="columnheader">时效</span>
          <span role="columnheader">状态</span>
        </div>
        <div class="database-row" role="row">
          <strong role="cell" data-label="Bundle">{{ bundle.version }}</strong>
          <code role="cell" data-label="数据库版本">
            {{ bundle.trivy_db_version }} / {{ bundle.trivy_java_db_version }}
          </code>
          <span class="mono" role="cell" data-label="登记时间">
            {{ formatDateTime(bundle.registered_at) }}
          </span>
          <span class="age-cell" role="cell" data-label="时效">
            <strong class="mono">{{ bundle.age_days }} 天</strong>
            <small>阈值 {{ bundle.stale_after_days }} 天</small>
          </span>
          <span
            class="database-state"
            :class="`database-state--${bundle.status}`"
            role="cell"
            data-label="状态"
          >
            {{ databaseStatusLabels[bundle.status] }}
          </span>
        </div>
        <footer class="command-footer">
          <code>{{ bundle.content_sha256 }}</code>
        </footer>
      </div>
    </section>
  </div>
</template>

<style scoped>
.analyzer-status {
  display: grid;
  min-width: 0;
  gap: 14px;
  container: analyzer-live / inline-size;
}

.analyzer-section,
.database-section {
  min-width: 0;
  overflow: hidden;
}

.section-heading {
  display: flex;
  min-height: 74px;
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

.section-heading button {
  display: inline-flex;
  min-height: 32px;
  flex: 0 0 auto;
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

.analyzer-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.analyzer-row {
  display: grid;
  min-width: 0;
  grid-template-columns: 34px minmax(0, 1fr) minmax(100px, auto) auto;
  align-items: center;
  gap: 10px;
  min-height: 112px;
  padding: 11px 16px;
  border-right: 1px solid #e7ebeb;
  border-bottom: 1px solid #e7ebeb;
}

.analyzer-readiness {
  display: grid;
  min-width: 0;
  grid-column: 2 / -1;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 5px 10px;
}

.worker-kinds {
  display: flex;
  min-width: 0;
  flex-wrap: wrap;
  align-items: center;
  gap: 5px;
}

.worker-kinds > span {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 5px;
  border: 1px solid #dfc3c3;
  border-radius: 3px;
  color: #8b3838;
  background: #fff7f7;
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 8px;
}

.worker-kinds > span i {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: var(--red);
}

.worker-kinds > .worker-kind--ready {
  border-color: #b8d7d3;
  color: var(--teal-strong);
  background: #f1f8f7;
}

.worker-kinds > .worker-kind--ready i {
  background: var(--teal);
}

.worker-kinds small {
  color: var(--ink-400);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 8px;
}

.runtime-version {
  min-width: 0;
  overflow-wrap: anywhere;
  color: var(--ink-600);
  font-size: 8px;
}

.analyzer-readiness > p {
  min-width: 0;
  grid-column: 1 / -1;
  margin: 0;
  color: var(--ink-600);
  font-size: 9px;
  line-height: 1.45;
}

.analyzer-times {
  display: flex;
  min-width: 0;
  grid-column: 1 / -1;
  flex-wrap: wrap;
  gap: 4px 12px;
  color: var(--ink-400);
  font-size: 8px;
}

.analyzer-row:nth-child(2n) {
  border-right: 0;
}

.analyzer-icon {
  display: grid;
  width: 32px;
  height: 32px;
  place-items: center;
  border: 1px solid #c0d1e4;
  border-radius: 4px;
  color: var(--blue);
  background: #f2f6fa;
}

.analyzer-identity,
.analyzer-version {
  min-width: 0;
}

.analyzer-identity strong,
.analyzer-identity span,
.analyzer-version code,
.analyzer-version small {
  display: block;
  overflow-wrap: anywhere;
}

.analyzer-identity strong {
  color: var(--ink-800);
  font-size: 11px;
}

.analyzer-identity span,
.analyzer-version small {
  margin-top: 3px;
  color: var(--ink-400);
  font-size: 9px;
}

.analyzer-version code {
  color: var(--ink-600);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 9px;
}

.state-label {
  display: inline-flex;
  min-height: 22px;
  align-items: center;
  gap: 5px;
  padding: 2px 6px;
  border: 1px solid #b8d7d3;
  border-radius: 3px;
  color: var(--teal-strong);
  background: #f1f8f7;
  font-size: 9px;
  font-weight: 700;
  white-space: nowrap;
}

.state-label i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--teal);
}

.state-label--unavailable {
  border-color: #e4bebe;
  color: var(--red);
  background: #fff5f5;
}

.state-label--unavailable i {
  background: var(--red);
}

.database-count {
  color: var(--ink-400);
  font-size: 9px;
}

.stale-alert {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 17px;
  border-bottom: 1px solid #decba7;
  color: var(--amber);
  background: #fff9ef;
}

.stale-alert span,
.stale-alert strong,
.stale-alert small {
  display: block;
}

.stale-alert strong {
  font-size: 10px;
}

.stale-alert small {
  margin-top: 2px;
  color: var(--ink-600);
  font-size: 9px;
}

.database-table__header,
.database-row {
  display: grid;
  min-width: 0;
  grid-template-columns:
    minmax(120px, 0.65fr) minmax(170px, 1.2fr)
    minmax(150px, 0.9fr) minmax(90px, 0.45fr) minmax(90px, 0.45fr);
  align-items: center;
  gap: 12px;
  padding: 10px 17px;
}

.database-table__header {
  color: var(--ink-600);
  background: #f7f9f9;
  font-size: 9px;
  font-weight: 700;
}

.database-row {
  min-height: 58px;
  border-top: 1px solid #e7ebeb;
  color: var(--ink-600);
  font-size: 9px;
}

.database-row > strong {
  color: var(--ink-800);
  font-size: 10px;
}

.database-row code {
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  overflow-wrap: anywhere;
}

.age-cell strong,
.age-cell small {
  display: block;
}

.age-cell small {
  margin-top: 2px;
  color: var(--ink-400);
  font-size: 8px;
}

.database-state {
  justify-self: start;
  padding: 2px 6px;
  border: 1px solid #b8d7d3;
  border-radius: 3px;
  color: var(--teal-strong);
  background: #f1f8f7;
  font-weight: 700;
  white-space: nowrap;
}

.database-state--stale {
  border-color: #decba7;
  color: var(--amber);
  background: #fff9ef;
}

.command-footer {
  display: flex;
  min-height: 52px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 9px 17px;
  border-top: 1px solid var(--line);
  color: var(--ink-400);
  background: #f7f9f9;
  font-size: 9px;
}

.command-buttons {
  display: flex;
  gap: 7px;
}

.command-buttons button {
  display: inline-flex;
  min-height: 30px;
  align-items: center;
  gap: 5px;
  padding: 4px 8px;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--ink-400);
  background: #eef1f1;
  cursor: not-allowed;
  font-size: 9px;
}

@container analyzer-live (max-width: 800px) {
  .analyzer-grid {
    grid-template-columns: 1fr;
  }

  .analyzer-row {
    border-right: 0;
  }

  .database-table__header {
    display: none;
  }

  .database-row {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .database-row > [role="cell"]::before {
    display: block;
    margin-bottom: 4px;
    color: var(--ink-400);
    content: attr(data-label);
    font-size: 8px;
  }
}

@container analyzer-live (max-width: 520px) {
  .section-heading,
  .command-footer {
    align-items: flex-start;
    flex-direction: column;
  }

  .analyzer-row {
    grid-template-columns: 32px minmax(0, 1fr) auto;
  }

  .analyzer-version {
    grid-column: 2 / -1;
  }

  .analyzer-readiness {
    grid-column: 1 / -1;
    grid-template-columns: 1fr;
  }

  .runtime-version {
    grid-row: auto;
  }

  .database-row {
    grid-template-columns: 1fr;
    padding: 13px;
  }

  .command-buttons {
    width: 100%;
  }

  .command-buttons button {
    flex: 1;
    justify-content: center;
  }
}
</style>
