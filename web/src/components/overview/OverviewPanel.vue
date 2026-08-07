<script setup lang="ts">
import {
  AlertTriangle,
  ArrowRight,
  Clock3,
  FileCheck2,
  LoaderCircle,
  ShieldAlert,
} from 'lucide-vue-next'
import { computed, onMounted, shallowRef } from 'vue'
import { useRouter } from 'vue-router'

import { api, ApiError } from '@/api/client'
import type { ScanTask } from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { formatDateTime } from '@/utils/formatters'

const router = useRouter()
const tasks = shallowRef<ScanTask[]>([])
const loading = shallowRef(true)
const errorMessage = shallowRef('')

const activeStatuses = new Set([
  'UPLOADING',
  'QUEUED',
  'VALIDATING',
  'IDENTIFYING',
  'EXTRACTING',
  'INDEXING',
  'SCANNING',
  'REPORTING',
  'RUNNING',
  'CANCEL_REQUESTED',
])

const running = computed(
  () => tasks.value.filter((task) => activeStatuses.has(task.status.toUpperCase())).length,
)
const queued = computed(
  () => tasks.value.filter((task) => task.status.toUpperCase() === 'QUEUED').length,
)
const attention = computed(
  () => tasks.value.filter((task) => {
    const risk = task.risk_level.toUpperCase()
    return (
      task.status.toUpperCase() === 'FAILED' ||
      risk === 'HIGH' ||
      risk === 'CRITICAL'
    )
  }).length,
)

function activityTone(status: ScanTask['status']): string {
  const normalized = status.toUpperCase()
  if (activeStatuses.has(normalized)) return 'active'
  if (normalized === 'PARTIAL_SUCCEEDED' || normalized === 'PARTIAL') return 'partial'
  return normalized.toLowerCase()
}

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    const result = await api.listTasks({ page_size: 8 })
    tasks.value = result.items
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '任务状态读取失败'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <StatePanel v-if="loading" class="surface-panel" kind="loading" />
  <StatePanel
    v-else-if="errorMessage"
    class="surface-panel"
    kind="error"
    :description="errorMessage"
    retryable
    @retry="load"
  />
  <div v-else class="overview">
    <dl class="metrics" aria-label="任务摘要">
      <div class="metric">
        <span class="metric__icon metric__icon--blue">
          <FileCheck2 :size="19" aria-hidden="true" />
        </span>
        <div class="metric__copy"><dt>最近任务</dt><dd>{{ tasks.length }}</dd></div>
      </div>
      <div class="metric">
        <span class="metric__icon metric__icon--teal">
          <LoaderCircle :size="19" aria-hidden="true" />
        </span>
        <div class="metric__copy"><dt>最近活动</dt><dd>{{ running }}</dd></div>
      </div>
      <div class="metric">
        <span class="metric__icon metric__icon--red">
          <ShieldAlert :size="19" aria-hidden="true" />
        </span>
        <div class="metric__copy"><dt>最近待关注</dt><dd>{{ attention }}</dd></div>
      </div>
      <div class="metric">
        <span class="metric__icon"><Clock3 :size="19" aria-hidden="true" /></span>
        <div class="metric__copy"><dt>最近排队</dt><dd>{{ queued }}</dd></div>
      </div>
    </dl>

    <section class="activity surface-panel">
      <header class="section-heading">
        <h2>最近任务</h2>
        <el-button text @click="router.push({ name: 'tasks' })">
          <span>查看全部</span>
          <ArrowRight :size="15" aria-hidden="true" />
        </el-button>
      </header>
      <StatePanel v-if="tasks.length === 0" kind="empty" title="暂无检测任务" />
      <div v-else class="activity-list">
        <button
          v-for="task in tasks"
          :key="task.id"
          class="activity-row"
          type="button"
          @click="router.push({ name: 'task-detail', params: { id: task.id } })"
        >
          <span
            class="activity-row__marker"
            :class="`activity-row__marker--${activityTone(task.status)}`"
            aria-hidden="true"
          />
          <span class="activity-row__copy">
            <strong>{{ task.name }}</strong>
            <small class="mono">{{ task.input_type }} / {{ task.id }}</small>
          </span>
          <span class="activity-row__badges">
            <StatusBadge :value="task.status" kind="status" />
            <StatusBadge :value="task.risk_level" kind="risk" />
          </span>
          <time :datetime="task.created_at">{{ formatDateTime(task.created_at) }}</time>
        </button>
      </div>
    </section>

    <div v-if="attention > 0" class="attention-strip">
      <AlertTriangle :size="16" aria-hidden="true" />
      <span>{{ attention }} 个最近任务需要关注</span>
    </div>
  </div>
</template>

<style scoped>
.overview {
  display: grid;
  gap: 18px;
  container: overview / inline-size;
}

.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  padding: 0;
  margin: 0;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: #fff;
}

.metric {
  display: flex;
  min-height: 96px;
  align-items: center;
  gap: 13px;
  padding: 18px;
  border-right: 1px solid var(--line);
}

.metric:last-child {
  border-right: 0;
}

.metric__icon {
  display: grid;
  width: 38px;
  height: 38px;
  flex: 0 0 38px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: 5px;
  color: var(--ink-600);
  background: #f4f6f6;
}

.metric__icon--teal {
  border-color: #bdd5d2;
  color: var(--teal);
  background: #f1f8f7;
}

.metric__icon--blue {
  border-color: #c0d1e4;
  color: var(--blue);
  background: #f2f6fa;
}

.metric__icon--red {
  border-color: #e3c5c5;
  color: var(--red);
  background: #fff5f5;
}

.metric__copy {
  min-width: 0;
}

.metric__copy dt,
.metric__copy dd {
  display: block;
  margin: 0;
}

.metric__copy dt {
  color: var(--ink-600);
  font-size: 11px;
  overflow-wrap: anywhere;
}

.metric__copy dd {
  margin-top: 5px;
  color: var(--ink-950);
  font-family: "IBM Plex Mono", Consolas, monospace;
  font-size: 21px;
  font-weight: 700;
}

.section-heading {
  display: flex;
  min-height: 52px;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px 0 18px;
  border-bottom: 1px solid var(--line);
}

.section-heading h2 {
  margin: 0;
  color: var(--ink-800);
  font-size: 14px;
}

.section-heading :deep(.el-button > span) {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}

.activity-list {
  display: grid;
}

.activity-row {
  display: grid;
  min-height: 64px;
  grid-template-columns: 5px minmax(220px, 1fr) auto 142px;
  align-items: center;
  gap: 14px;
  padding: 8px 16px;
  border: 0;
  border-bottom: 1px solid #e7eaeb;
  color: inherit;
  background: #fff;
  text-align: left;
  cursor: pointer;
}

.activity-row:last-child {
  border-bottom: 0;
}

.activity-row:hover {
  background: #f7f9f9;
}

.activity-row:focus-visible {
  position: relative;
  z-index: 1;
}

.activity-row__marker {
  width: 3px;
  height: 26px;
  border-radius: 2px;
  background: var(--ink-400);
}

.activity-row__marker--active {
  background: var(--blue);
}

.activity-row__marker--succeeded {
  background: var(--teal);
}

.activity-row__marker--failed {
  background: var(--red);
}

.activity-row__marker--partial {
  background: var(--amber);
}

.activity-row__copy {
  min-width: 0;
}

.activity-row__badges {
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: flex-end;
  gap: 7px;
}

.activity-row__copy strong,
.activity-row__copy small {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.activity-row__copy strong {
  color: var(--ink-800);
  font-size: 13px;
}

.activity-row__copy small,
.activity-row time {
  margin-top: 4px;
  color: var(--ink-400);
  font-size: 10px;
}

.attention-strip {
  display: flex;
  min-height: 42px;
  align-items: center;
  gap: 9px;
  padding: 8px 13px;
  border: 1px solid #dfc8a2;
  border-left: 3px solid var(--amber);
  border-radius: 4px;
  color: #7f541b;
  background: #fffaf1;
  font-size: 12px;
}

@container overview (max-width: 980px) {
  .metrics {
    grid-template-columns: 1fr 1fr;
  }

  .metric:nth-child(2) {
    border-right: 0;
  }

  .metric:nth-child(-n + 2) {
    border-bottom: 1px solid var(--line);
  }

  .activity-row {
    grid-template-columns: 5px minmax(180px, 1fr) auto;
  }

  .activity-row time {
    display: none;
  }
}

@container overview (max-width: 620px) {
  .metric {
    min-height: 82px;
    gap: 10px;
    padding: 14px;
  }

  .metric__icon {
    width: 34px;
    height: 34px;
    flex-basis: 34px;
  }

  .activity-row {
    grid-template-areas:
      "marker copy"
      "marker badges";
    grid-template-columns: 4px minmax(0, 1fr);
    gap: 8px 10px;
    padding: 11px 12px;
  }

  .activity-row__marker {
    grid-area: marker;
    width: 4px;
    height: auto;
    align-self: stretch;
  }

  .activity-row__copy {
    grid-area: copy;
  }

  .activity-row__badges {
    grid-area: badges;
    justify-content: flex-start;
    flex-wrap: wrap;
  }

  .section-heading {
    padding-right: 10px;
    padding-left: 14px;
  }
}
</style>
