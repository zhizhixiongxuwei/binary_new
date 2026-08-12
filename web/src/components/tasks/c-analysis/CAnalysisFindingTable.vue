<script setup lang="ts">
import { ChevronDown, Code2, LoaderCircle, SearchX } from 'lucide-vue-next'

import type { CAnalysisFinding } from '@/api/types'

defineProps<{
  findings: readonly CAnalysisFinding[]
  loading: boolean
  loadingMore: boolean
  hasMore: boolean
}>()

const emit = defineEmits<{
  select: [finding: CAnalysisFinding]
  loadMore: []
}>()

function locationLabel(finding: CAnalysisFinding): string {
  const location = finding.location
  return `${location.start_line}:${location.start_column}`
}
</script>

<template>
  <div v-if="loading" class="finding-state" role="status">
    <LoaderCircle class="spin" :size="20" aria-hidden="true" />
    <span>正在读取检测发现</span>
  </div>
  <div v-else-if="findings.length === 0" class="finding-state">
    <SearchX :size="20" aria-hidden="true" />
    <span>当前检测版本和筛选条件下没有发现。</span>
  </div>
  <template v-else>
    <div class="finding-table-scroll" tabindex="0" aria-label="C 源码检测结果表格滚动区域">
      <table class="finding-table">
        <caption class="sr-only">选择一条检测发现查看源码片段</caption>
        <thead>
          <tr>
            <th scope="col">严重度</th>
            <th scope="col">CWE</th>
            <th scope="col">规则</th>
            <th scope="col">函数</th>
            <th scope="col">位置</th>
            <th scope="col">检测结论</th>
            <th scope="col">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="finding in findings"
            :key="finding.id"
            tabindex="0"
            @click="$emit('select', finding)"
            @keydown.enter.self="emit('select', finding)"
            @keydown.space.self.prevent="emit('select', finding)"
          >
            <td>
              <span class="severity" :class="`severity--${finding.severity.toLowerCase()}`">
                {{ finding.severity }}
              </span>
            </td>
            <td><code>{{ finding.cwe }}</code></td>
            <td><code class="rule">{{ finding.rule_id }}</code></td>
            <td>
              <strong class="function-name" :title="finding.function.name">
                {{ finding.function.name }}
              </strong>
              <small>{{ finding.function.address }}</small>
            </td>
            <td><code>{{ locationLabel(finding) }}</code></td>
            <td><span class="message" :title="finding.message">{{ finding.message }}</span></td>
            <td class="finding-actions">
              <button
                type="button"
                title="查看代码片段"
                :aria-label="`查看 ${finding.function.name} 的代码片段`"
                @click.stop="emit('select', finding)"
              >
                <Code2 :size="14" aria-hidden="true" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <footer v-if="hasMore" class="load-more">
      <el-button :disabled="loadingMore" :loading="loadingMore" @click="$emit('loadMore')">
        <ChevronDown v-if="!loadingMore" :size="14" aria-hidden="true" />
        加载更多
      </el-button>
    </footer>
  </template>
</template>

<style scoped>
.finding-state {
  display: grid;
  min-height: 190px;
  place-items: center;
  align-content: center;
  gap: 9px;
  color: var(--ink-400);
  font-size: 11px;
}

.finding-table-scroll {
  min-width: 0;
  max-height: 560px;
  overflow: auto;
}

.finding-table {
  width: 100%;
  min-width: 950px;
  border-collapse: collapse;
  table-layout: fixed;
}

.finding-table th,
.finding-table td {
  min-width: 0;
  padding: 9px 12px;
  border-bottom: 1px solid #e5e9ea;
  text-align: left;
  vertical-align: middle;
}

.finding-table th {
  position: sticky;
  z-index: 1;
  top: 0;
  color: var(--ink-600);
  background: #f2f5f5;
  font-size: 9px;
  font-weight: 700;
}

.finding-table th:nth-child(1) { width: 90px; }
.finding-table th:nth-child(2) { width: 90px; }
.finding-table th:nth-child(3) { width: 176px; }
.finding-table th:nth-child(4) { width: 190px; }
.finding-table th:nth-child(5) { width: 82px; }
.finding-table th:nth-child(7) { width: 58px; }

.finding-table tbody tr {
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
  font-size: 10px;
}

.finding-table tbody tr:hover,
.finding-table tbody tr:focus-visible { background: #f2f8f7; }
.finding-table code { font-size: 9px; }
.rule,
.message,
.function-name {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.function-name { color: var(--ink-800); font-size: 10px; }
.finding-table small { display: block; margin-top: 2px; color: var(--ink-400); font-size: 8px; }

.finding-actions { text-align: center !important; }
.finding-actions button {
  display: inline-grid;
  width: 28px;
  height: 28px;
  place-items: center;
  padding: 0;
  border: 1px solid #c7d3d3;
  border-radius: 4px;
  color: #246c68;
  background: #f7fbfa;
  cursor: pointer;
}
.finding-actions button:hover { border-color: #6fa29e; background: #eaf5f3; }
.finding-actions button:focus-visible { outline: 2px solid #3f8580; outline-offset: 2px; }

.severity {
  display: inline-flex;
  min-width: 64px;
  min-height: 22px;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--line-strong);
  border-radius: 3px;
  font-size: 8px;
  font-weight: 800;
}
.severity--critical { border-color: #ce9599; color: #8f252d; background: #fff1f2; }
.severity--high { border-color: #d9a18c; color: #9a4428; background: #fff4ef; }
.severity--medium { border-color: #dcc18b; color: #815c13; background: #fff9eb; }
.severity--low { border-color: #9dc5d1; color: #28697b; background: #f0f9fb; }

.load-more { display: grid; place-items: center; padding: 10px; border-top: 1px solid var(--line); }
.spin { animation: finding-spin 1s linear infinite; }
@keyframes finding-spin { to { transform: rotate(360deg); } }
</style>
