<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import axios from 'axios';
import { ElMessage } from 'element-plus';

// ── 1. 基础配置（根据你的实际环境调整路径或变量） ──
const INDEXER_URL = '/wazuh-indexer/wazuh-archives-*/_search';
const indexerUser = import.meta.env.VITE_WAZUH_INDEXER_USER || 'admin';
const indexerPass = import.meta.env.VITE_WAZUH_INDEXER_PASSWORD || 'secret';
const INDEXER_AUTH = btoa(`${indexerUser}:${indexerPass}`);

// ── 2. 响应式状态 ──
const archivesList = ref<any[]>([]);
const isLoading = ref(false);
const errorMsg = ref('');
const selectedTimeRange = ref('1h');
const fuzzyKeyword = ref('');

// ── JSON 详情弹窗状态 ──
const detailVisible = ref(false);
const selectedLog = ref<any>(null);

// ── 分页状态 ──
const currentPage = ref(1);
const pageSize = 50;
const total = ref(0);

// ── 3. 核心查询函数 ──
const timeMap: Record<string, string> = { '1h': 'now-1h', '1d': 'now-1d', '7d': 'now-7d' };

const executeArchivesSearch = async () => {
  isLoading.value = true;
  errorMsg.value = '';

  const must: any[] = [
    { range: { "timestamp": { "gte": timeMap[selectedTimeRange.value] } } }
  ];

  // 模糊查询（参照 alerts_query 实现）
  const kw = fuzzyKeyword.value.trim();
  if (kw) {
    must.push({
      query_string: {
        query: `*${kw}*`,
        analyze_wildcard: true
      }
    });
  }

  const startTime = performance.now();
  try {
    const response = await axios.post(
      INDEXER_URL,
      {
        size: pageSize,
        from: (currentPage.value - 1) * pageSize,
        sort: [{ "timestamp": "desc" }],
        query: {
          bool: { must }
        }
      },
      {
        headers: {
          'Authorization': `Basic ${INDEXER_AUTH}`,
          'Content-Type': 'application/json'
        }
      }
    );

    archivesList.value = response.data.hits.hits.map((hit: any) => hit._source);
    total.value = response.data.hits.total?.value ?? response.data.hits.hits.length;
  } catch (err: any) {
    console.error(err);
    errorMsg.value = `数据获取失败: ${err.message || '未知错误'}`;
  } finally {
    isLoading.value = false;
    // 查询耗时统计：每次查询结束后在顶部弹出提示
    const elapsed = performance.now() - startTime;
    const duration = elapsed >= 1000 ? `${(elapsed / 1000).toFixed(2)} s` : `${Math.round(elapsed)} ms`;
    ElMessage.info(`查询耗时 ${duration}`);
  }
};

const fetchArchives = async () => {
  currentPage.value = 1;
  await executeArchivesSearch();
};

const changePage = (page: number) => {
  if (page < 1 || page > totalPages.value) return;
  currentPage.value = page;
  executeArchivesSearch();
};

// ── 分页计算属性 ──
const totalPages = computed(() => Math.ceil(total.value / pageSize) || 1);

const visiblePages = computed(() => {
  const total = totalPages.value;
  const cur = currentPage.value;
  const pages: (number | string)[] = [];
  if (total <= 7) {
    for (let i = 1; i <= total; i++) pages.push(i);
    return pages;
  }
  pages.push(1);
  if (cur > 3) pages.push('…');
  const start = Math.max(2, cur - 1);
  const end = Math.min(total - 1, cur + 1);
  for (let i = start; i <= end; i++) pages.push(i);
  if (cur < total - 2) pages.push('…');
  pages.push(total);
  return pages;
});

const formatTime = (timestamp: string) => {
  if (!timestamp) return '--';
  try {
    return new Date(timestamp).toLocaleString();
  } catch {
    return timestamp;
  }
};

const getLevelColor = (level: any) => {
  const l = Number(level);
  if (l >= 12) return '#f5023d';
  if (l >= 8) return '#e3b337';
  return '#31ABE3';
};

// ── JSON 弹窗 & 复制 ──
const openJsonDetail = (log: any) => {
  selectedLog.value = log;
  detailVisible.value = true;
};

const copyToClipboard = (text: string) => {
  navigator.clipboard.writeText(text).then(() => {
    alert("JSON 内容已复制");
  });
};

onMounted(() => {
  fetchArchives();
});
</script>

<template>
  <div class="aq-root flex flex-col h-full">
    <!-- Tool Bar -->
    <div class="aq-toolbar flex items-center justify-between flex-shrink-0 px-4 py-3">
      <div class="flex items-center gap-1.5">
        <span class="toolbar-badge">📋 原始日志查询</span>
        <span class="toolbar-hint">Wazuh Archives 归档数据检索</span>
      </div>

      <div class="flex items-center gap-1">
        <button
          v-for="t in ['1h', '1d', '7d']"
          :key="t"
          :class="['time-chip', selectedTimeRange === t ? 'time-chip--active' : 'time-chip--inactive']"
          @click="selectedTimeRange = t; fetchArchives()"
        >
          {{ t === '1h' ? '1小时' : t === '1d' ? '24小时' : '一周' }}
        </button>
        <button
          class="btn-refresh ml-1"
          :disabled="isLoading"
          @click="fetchArchives()"
        >
          {{ isLoading ? '刷新中...' : '刷新' }}
        </button>
      </div>
    </div>

    <!-- ── 模糊搜索（参照 alerts_query 实现） ── -->
    <div class="fz-search-area flex items-center gap-2 px-4 py-2">
      <div class="fz-search-wrap flex-1 relative" style="min-width:200px">
        <div :class="['fz-input-wrap', fuzzyKeyword ? 'fz-input-wrap--active' : '']">
          <span class="fz-search-prefix">🔎</span>
          <input
            v-model="fuzzyKeyword"
            placeholder="模糊搜索 (任意关键字)"
            @keyup.enter="fetchArchives"
            class="fz-search-input"
          />
          <button v-if="fuzzyKeyword" class="fz-search-clear" @click="fuzzyKeyword = ''; fetchArchives()">×</button>
        </div>
      </div>
      <button class="fz-btn-query flex-shrink-0" @click="fetchArchives" :disabled="isLoading">
        {{ isLoading ? '搜索中...' : '搜索' }}
      </button>
    </div>

    <!-- Body (scrollable) -->
    <div class="aq-body flex-1 overflow-y-auto px-4 pb-4">
      <!-- Loading state -->
      <div v-if="isLoading && archivesList.length === 0" class="flex items-center justify-center h-40">
        <div class="loading-spinner"></div>
      </div>

      <!-- Error state -->
      <div v-else-if="errorMsg" class="error-card">
        <span class="error-icon">⚠️</span>
        <div class="error-text">
          <p class="error-title">数据拉取失败</p>
          <p class="error-detail">{{ errorMsg }}</p>
        </div>
        <button class="btn-retry" @click="fetchArchives()">重试</button>
      </div>

      <!-- Data table -->
      <div v-else-if="archivesList.length > 0" class="archives-table-wrap">
        <div class="aq-table-header grid grid-cols-[1.8fr_0.8fr_0.6fr_2fr_0.8fr] gap-1 px-4 py-2.5 text-xs font-semibold">
          <span class="text-center">时间戳</span>
          <span class="text-center">主机</span>
          <span class="text-center">级别</span>
          <span class="text-center">事件摘要</span>
          <span class="text-center">明细</span>
        </div>

        <div class="aq-table-body">
          <div
            v-for="(log, index) in archivesList"
            :key="index"
            class="aq-row grid grid-cols-[1.8fr_0.8fr_0.6fr_2fr_0.8fr] gap-1 px-2 py-2.5 rounded-md transition-all duration-200"
          >
            <span class="text-center text-xs truncate text-[var(--muted-foreground)] font-mono">
              {{ formatTime(log.timestamp) }}
            </span>
            <span class="text-center text-xs truncate text-[var(--foreground)] font-mono">
              {{ log.agent?.name || 'Manager' }}
            </span>
            <span
              class="text-center text-xs font-bold font-mono"
              :style="{ color: getLevelColor(log.rule?.level) }"
            >
              L{{ log.rule?.level || '?' }}
            </span>
            <span class="text-center text-xs truncate text-[var(--muted-foreground)]">
              {{ log.rule?.description || log.full_log || log.message || '--' }}
            </span>
            <span class="text-center text-xs">
              <button class="json-btn" @click="openJsonDetail(log)">JSON</button>
            </span>
          </div>
        </div>
      </div>

      <!-- Empty state -->
      <div v-else class="flex flex-col items-center justify-center h-40 text-center gap-2">
        <div class="text-2xl opacity-30">📭</div>
        <p class="text-sm font-medium text-[var(--muted-foreground)]">暂无归档日志数据</p>
        <span class="text-xs text-[var(--muted-foreground)] opacity-50 max-w-[280px] leading-relaxed">
          过去 1 小时内未检测到归档日志，请确认 Filebeat 是否在持续写入。
        </span>
      </div>
    </div>

    <!-- ── Archives Pagination ── -->
    <div v-if="archivesList.length > 0" class="pagination-bar">
      <span class="pagination-info">共 {{ total }} 条</span>
      <div class="pagination-controls">
        <button
          class="pg-btn"
          :disabled="currentPage <= 1"
          @click="changePage(currentPage - 1)"
        >‹ 上一页</button>
        <template v-for="p in visiblePages" :key="p">
          <span v-if="p === '…'" class="pg-ellipsis">…</span>
          <button
            v-else
            :class="['pg-btn', 'pg-num', currentPage === p ? 'pg-num--active' : '']"
            @click="changePage(p as number)"
          >{{ p }}</button>
        </template>
        <button
          class="pg-btn"
          :disabled="currentPage >= totalPages"
          @click="changePage(currentPage + 1)"
        >下一页 ›</button>
      </div>
    </div>

    <!-- ── JSON Detail Modal ── -->
    <Teleport to="body">
      <div v-if="detailVisible" class="modal-mask" @click.self="detailVisible = false">
        <div class="modal-panel">
          <div class="modal-header">
            <h3 class="text-sm font-bold text-[#31ABE3] m-0">归档日志 JSON</h3>
            <div class="flex items-center gap-2">
              <button class="modal-btn modal-btn--copy" @click="copyToClipboard(JSON.stringify(selectedLog, null, 2))">复制 JSON</button>
              <button class="modal-btn modal-btn--close" @click="detailVisible = false">关闭</button>
            </div>
          </div>
          <div class="modal-body">
            <pre class="modal-pre">{{ JSON.stringify(selectedLog, null, 2) }}</pre>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped lang="scss">
// ── Root ──
.aq-root {
  background: var(--background, #ffffff);
  border-radius: 8px;
  border: 1px solid #e5e7eb;
  position: relative;
  overflow: hidden;
  height: 100%;
}

// ── Toolbar ──
.aq-toolbar {
  border-bottom: 1px solid #e5e7eb;
  background: #f8fafc;
}

.toolbar-badge {
  font-size: 12px;
  font-weight: 600;
  color: #1d4ed8;
  background: rgba(29, 78, 216, 0.06);
  padding: 3px 12px;
  border-radius: 999px;
  border: 1px solid rgba(29, 78, 216, 0.1);
}

.toolbar-hint {
  font-size: 11px;
  color: var(--muted-foreground, #7c8a9e);
  margin-left: 8px;
  opacity: 0.6;
}

// ── Time Chips ──
.time-chip {
  padding: 3px 10px;
  font-size: 11px;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s ease;
  border: none;

  &--inactive {
    background: transparent;
    color: var(--muted-foreground, #7c8a9e);
    border: 1px solid var(--border, rgba(49, 171, 227, 0.12));
    &:hover { border-color: rgba(49, 171, 227, 0.3); color: var(--foreground); }
  }

  &--active {
    background: rgba(49, 171, 227, 0.12);
    color: #31ABE3;
    border: 1px solid rgba(49, 171, 227, 0.25);
  }
}

.btn-refresh {
  background: rgba(49, 171, 227, 0.1);
  border: 1px solid var(--border, rgba(49, 171, 227, 0.12));
  color: #31ABE3;
  padding: 3px 12px;
  font-size: 11px;
  font-weight: 600;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s ease;

  &:hover:not(:disabled) {
    background: rgba(49, 171, 227, 0.18);
    border-color: rgba(49, 171, 227, 0.3);
  }

  &:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
}

// ── Fuzzy Search Bar（参照 alerts_query 模糊查询 UI） ──
.fz-search-area {
  z-index: 10;
  border-bottom: 1px solid #e5e7eb;
  background: #f8fafc;
}

.fz-search-wrap {
  position: relative;
}

.fz-input-wrap {
  display: flex;
  align-items: center;
  background: #f9fafb;
  border: 1px solid #d1d5db;
  border-radius: 8px;
  padding: 0 12px;
  transition: all 0.2s ease;

  &:focus-within,
  &--active {
    border-color: rgba(49, 171, 227, 0.3);
    box-shadow: 0 0 0 2px rgba(49, 171, 227, 0.06);
  }
}

.fz-search-prefix {
  color: var(--muted-foreground, #7c8a9e);
  font-size: 13px;
  margin-right: 6px;
  opacity: 0.6;
}

.fz-search-input {
  flex: 1;
  background: transparent;
  border: none;
  padding: 9px 8px;
  color: #1f2937;
  outline: none;
  font-family: ui-monospace, monospace;
  font-size: 12.5px;

  &::placeholder {
    color: var(--muted-foreground, #7c8a9e);
    opacity: 0.4;
  }
}

.fz-search-clear {
  background: none;
  border: none;
  color: var(--muted-foreground, #7c8a9e);
  font-size: 18px;
  cursor: pointer;
  opacity: 0.4;
  padding: 0;
  line-height: 1;
  &:hover { opacity: 0.8; color: var(--foreground); }
}

.fz-btn-query {
  background: rgba(49, 171, 227, 0.1);
  border: 1px solid var(--border, rgba(49, 171, 227, 0.12));
  color: #31ABE3;
  padding: 0 16px;
  font-size: 12px;
  font-weight: 600;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
  white-space: nowrap;
  height: 38px;

  &:hover:not(:disabled) {
    background: rgba(49, 171, 227, 0.18);
    border-color: rgba(49, 171, 227, 0.3);
  }

  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
}

// ── Body ──
.aq-body {
  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb {
    background: color-mix(in oklab, var(--muted-foreground, #7c8a9e) 15%, transparent);
    border-radius: 2px;
  }
}

// ── Loading ──
.loading-spinner {
  width: 28px;
  height: 28px;
  border: 3px solid color-mix(in oklab, #31ABE3 10%, transparent);
  border-top-color: #1d4ed8;
  border-radius: 50%;
  animation: aqSpin 1s linear infinite;
}

@keyframes aqSpin {
  to { transform: rotate(360deg); }
}

// ── Error Card ──
.error-card {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  margin-top: 12px;
  background: rgba(245, 2, 61, 0.04);
  border: 1px solid rgba(245, 2, 61, 0.12);
  border-radius: 8px;
  padding: 12px 14px;

  .error-icon { font-size: 16px; line-height: 1.4; flex-shrink: 0; }

  .error-text {
    flex: 1;
    .error-title { font-size: 12px; font-weight: 600; color: #f5023d; margin: 0 0 2px; }
    .error-detail { font-size: 11px; color: var(--muted-foreground, #7c8a9e); margin: 0; }
  }

  .btn-retry {
    flex-shrink: 0;
    background: rgba(49, 171, 227, 0.1);
    border: 1px solid var(--border, rgba(49, 171, 227, 0.12));
    color: #31ABE3;
    padding: 4px 12px;
    font-size: 11px;
    font-weight: 600;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s ease;

    &:hover {
      background: rgba(49, 171, 227, 0.18);
      border-color: rgba(49, 171, 227, 0.3);
    }
  }
}

// ── Table ──
.aq-table-header {
  background: #f8fafc;
  color: var(--muted-foreground, #7c8a9e);
  border-bottom: 1px solid #e5e7eb;
}

.aq-table-body {
  position: relative;
}

.aq-row {
  border-bottom: 1px solid color-mix(in oklab, #e5e7eb 50%, transparent);
  cursor: default;
  transition: all 0.15s ease;

  &:hover {
    background: rgba(49, 171, 227, 0.04);
  }

  &:last-child { border-bottom: none; }
}

// ── JSON Button ──
.json-btn {
  display: inline-block;
  padding: 1px 8px;
  font-size: 10px;
  font-weight: 600;
  font-family: ui-monospace, monospace;
  color: #31ABE3;
  background: rgba(49, 171, 227, 0.06);
  border: 1px solid rgba(49, 171, 227, 0.1);
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.15s ease;

  &:hover {
    background: rgba(49, 171, 227, 0.12);
    border-color: rgba(49, 171, 227, 0.25);
  }
}

// ── Modal ──
.modal-mask {
  position: fixed;
  inset: 0;
  background: rgba(255, 255, 255, 0.9);
  backdrop-filter: blur(4px);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 9999;
}

.modal-panel {
  width: 75%;
  max-height: 85vh;
  background: var(--card, #ffffff);
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 20px;
    border-bottom: 1px solid #e5e7eb;
  }

  .modal-body {
    flex: 1;
    min-height: 0;
    overflow: auto;
    padding: 16px 20px;
  }

  .modal-pre {
    margin: 0;
    color: #374151;
    font-family: 'Courier New', ui-monospace, monospace;
    font-size: 12.5px;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.6;
  }
}

.modal-btn {
  padding: 5px 14px;
  font-size: 12px;
  font-weight: 600;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s ease;
  border: none;

  &--copy {
    background: transparent;
    border: 1px solid var(--border, rgba(49, 171, 227, 0.12));
    color: #31ABE3;
    &:hover { background: rgba(49, 171, 227, 0.1); }
  }

  &--close {
    background: #31ABE3;
    color: #fff;
    &:hover { background: #00fdfa; color: #000; }
  }
}

// ── Pagination Bar（对齐 alerts_query / VulnerabilityQuery 风格） ──
.pagination-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 16px;
  border-top: 1px solid #e5e7eb;
  background: #f8fafc;
  flex-shrink: 0;
}

.pagination-info {
  font-size: 12px;
  color: var(--muted-foreground, #7c8a9e);
  white-space: nowrap;
}

.pagination-controls {
  display: flex;
  align-items: center;
  gap: 4px;
}

.pg-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 32px;
  height: 28px;
  padding: 0 10px;
  font-size: 12px;
  font-weight: 500;
  color: var(--muted-foreground, #7c8a9e);
  background: transparent;
  border: 1px solid var(--border, rgba(49, 171, 227, 0.12));
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s ease;
  white-space: nowrap;
  user-select: none;
}
.pg-btn:hover:not(:disabled) {
  color: #31ABE3;
  border-color: rgba(49, 171, 227, 0.3);
  background: rgba(49, 171, 227, 0.06);
}
.pg-btn:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

.pg-num {
  min-width: 28px;
  padding: 0 6px;
  font-family: ui-monospace, monospace;
}
.pg-num--active {
  color: #31ABE3;
  background: rgba(49, 171, 227, 0.1);
  border-color: rgba(49, 171, 227, 0.25);
  font-weight: 600;
  cursor: default;
}

.pg-ellipsis {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 20px;
  font-size: 13px;
  color: #7c8a9e;
  letter-spacing: 2px;
  user-select: none;
}
</style>
