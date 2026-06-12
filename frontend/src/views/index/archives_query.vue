<script setup lang="ts">
import { ref, onMounted } from 'vue';
import axios from 'axios';

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

// ── 3. 核心查询函数 ──
const fetchArchives = async () => {
  isLoading.value = true;
  errorMsg.value = '';

  const timeMap: Record<string, string> = { '1h': 'now-1h', '1d': 'now-1d', '7d': 'now-7d' };

  try {
    const response = await axios.post(
      INDEXER_URL,
      {
        size: 200,
        sort: [{ "timestamp": "desc" }],
        query: {
          bool: {
            must: [
              { range: { "timestamp": { "gte": timeMap[selectedTimeRange.value] } } }
            ]
          }
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
  } catch (err: any) {
    console.error(err);
    errorMsg.value = `数据获取失败: ${err.message || '未知错误'}`;
  } finally {
    isLoading.value = false;
  }
};

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

    <!-- Body -->
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
              <details class="json-details">
                <summary class="json-summary">JSON</summary>
                <div class="json-popup">
                  <pre class="json-pre"><code>{{ JSON.stringify(log, null, 2) }}</code></pre>
                </div>
              </details>
            </span>
          </div>
        </div>

        <div class="aq-footer text-center py-2 text-[10px] text-[var(--muted-foreground)] opacity-40 font-mono">
          共 {{ archivesList.length }} 条归档记录
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
  </div>
</template>

<style scoped lang="scss">
// ── Root ──
.aq-root {
  background: var(--background, #0a0e17);
  border-radius: 8px;
  border: 1px solid var(--border, rgba(49, 171, 227, 0.12));
  position: relative;
  overflow: hidden;
  height: 100%;
}

// ── Toolbar ──
.aq-toolbar {
  border-bottom: 1px solid var(--border, rgba(49, 171, 227, 0.12));
  background: color-mix(in oklab, var(--background, #0a0e17) 98%, #31ABE3);
}

.toolbar-badge {
  font-size: 12px;
  font-weight: 600;
  color: #00fdfa;
  background: rgba(0, 253, 250, 0.06);
  padding: 3px 12px;
  border-radius: 999px;
  border: 1px solid rgba(0, 253, 250, 0.1);
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
  border-top-color: #00fdfa;
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
  background: color-mix(in oklab, var(--background, #0a0e17) 96%, #31ABE3);
  color: var(--muted-foreground, #7c8a9e);
  border-bottom: 1px solid var(--border, rgba(49, 171, 227, 0.12));
}

.aq-table-body {
  position: relative;
}

.aq-row {
  border-bottom: 1px solid color-mix(in oklab, var(--border, rgba(49, 171, 227, 0.12)) 50%, transparent);
  cursor: default;
  transition: all 0.15s ease;

  &:hover {
    background: rgba(49, 171, 227, 0.04);
  }

  &:last-child { border-bottom: none; }
}

// ── JSON Details ──
.json-details {
  position: relative;
  display: inline-block;
}

.json-summary {
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
  list-style: none;

  &::-webkit-details-marker { display: none; }

  &:hover {
    background: rgba(49, 171, 227, 0.12);
    border-color: rgba(49, 171, 227, 0.25);
  }
}

.json-popup {
  position: absolute;
  top: calc(100% + 6px);
  right: 0;
  z-index: 50;
  width: 420px;
  max-height: 300px;
  overflow: auto;
  background: var(--code, #0d1117);
  border: 1px solid var(--border, rgba(49, 171, 227, 0.2));
  border-radius: 8px;
  box-shadow: 0 12px 30px rgba(0, 0, 0, 0.6);
  padding: 10px 12px;

  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb {
    background: color-mix(in oklab, var(--muted-foreground, #7c8a9e) 15%, transparent);
    border-radius: 2px;
  }
}

.json-pre {
  margin: 0;
  color: #a5d6ff;
  font-family: 'Courier New', ui-monospace, monospace;
  font-size: 11.5px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-all;
}

// ── Footer ──
.aq-footer {
  border-top: 1px solid var(--border, rgba(49, 171, 227, 0.12));
}
</style>
