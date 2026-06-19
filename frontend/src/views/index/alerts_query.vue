<script setup lang="ts">
import { ref, reactive, computed, onMounted, onBeforeUnmount } from "vue";
import { ElMessage } from "element-plus";
import axios from 'axios';

const props = defineProps<{
  attackAbstract?: {
    hosts?: string[];
    start_time?: string;
    end_time?: string;
    duration?: string;
    ioc_files?: string[];
    ioc_domains?: string[];
    ioc_processes?: string[];
    tactics?: string[];
    tactics_count?: number;
  } | null;
}>();

// ── 通用工具 ──
const indexerUser = import.meta.env.VITE_WAZUH_INDEXER_USER;
const indexerPass = import.meta.env.VITE_WAZUH_INDEXER_PASSWORD;
const INDEXER_AUTH = btoa(`${indexerUser}:${indexerPass}`);

const formatDateTime = (timestamp: string) => {
  return new Date(timestamp).toLocaleString();
};

// ─────────────────────────────────────────────
// 模块 A：近期告警监控（已有功能）
// ─────────────────────────────────────────────
const state = reactive({
  currentTab: 'alarm' as 'alarm' | 'history',
  alarmData: [] as any[],
  loading: false,
  selectedTimeRange: '1h',
  selectedLevel: 'all',
  detailVisible: false,
  selectedLog: null as any,
});

const copyToClipboard = (text: string) => {
  navigator.clipboard.writeText(text).then(() => {
    alert("JSON 内容已复制");
  });
};

const getWazuhAlerts = async () => {
  state.loading = true;
  try {
    const timeMap: Record<string, string> = { '1h': 'now-1h', '1d': 'now-1d', '7d': 'now-7d' };
    const levelOpt = levelOptions.find(o => o.key === state.selectedLevel);
    const levelCondition = levelOpt?.range
      ? { range: { "rule.level": { ...levelOpt.range } } }
      : { range: { "rule.level": { "gte": 10 } } };
    const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 50,
      sort: [{ "timestamp": "desc" }],
      query: {
        bool: {
          must: [
            levelCondition,
            { range: { "timestamp": { "gte": timeMap[state.selectedTimeRange] } } }
          ]
        }
      }
    }, {
      headers: {
        'Authorization': `Basic ${INDEXER_AUTH}`,
        'Content-Type': 'application/json'
      }
    });

    state.alarmData = res.data.hits.hits.map((item: any) => ({
      ...item._source,
      formattedTime: formatDateTime(item._source.timestamp),
      raw: JSON.stringify(item._source, null, 2)
    }));
  } catch (err) {
    console.error("数据拉取失败", err);
  } finally {
    state.loading = false;
  }
};

const changeTimeRange = (range: string) => {
  state.selectedTimeRange = range;
  getWazuhAlerts();
};

// ── 告警等级筛选 ──
const levelOptions = [
  { key: 'all', label: '全部等级', range: null },
  { key: '10-11', label: '低危 10-11', range: { gte: 10, lte: 11 } },
  { key: '12-13', label: '中危 12-13', range: { gte: 12, lte: 13 } },
  { key: '14-15', label: '高危 14-15', range: { gte: 14, lte: 15 } },
];

const changeLevelFilter = (level: string) => {
  state.selectedLevel = level;
  if (state.currentTab === 'alarm') {
    getWazuhAlerts();
  }
};

const showDetail = (item: any) => {
  state.selectedLog = item;
  state.detailVisible = true;
};

// ─────────────────────────────────────────────
// 模块 B：历史告警日志查询（从第一页 right-center.vue 移植）
// ─────────────────────────────────────────────
const searchText = ref("");
const allFields = ref<string[]>([]);
const showPanel = ref(false);
const historyLogs = ref<any[]>([]);
const historyLoading = ref(false);
const historyDetailVisible = ref(false);
const currentHistoryLog = ref<any>(null);

// 1. 获取字段字典 (Mapping)
const fetchAvailableFields = async () => {
  try {
    const res = await axios.get('/wazuh-indexer/wazuh-alerts-*/_mapping', {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}` }
    });
    const fields: string[] = [];
    const extractFields = (obj: any, path = '') => {
      for (const key in obj) {
        const fullPath = path ? `${path}.${key}` : key;
        if (obj[key].properties) extractFields(obj[key].properties, fullPath);
        else fields.push(fullPath);
      }
    };
    const firstIndex = Object.keys(res.data)[0];
    extractFields(res.data[firstIndex].mappings.properties);
    allFields.value = Array.from(new Set(fields));
  } catch (err) { console.error("字段加载失败", err); }
};

// 2. 字段搜索建议
const filteredFields = computed(() => {
  if (!searchText.value) return [];
  const words = searchText.value.split(/\s+/);
  const lastWord = words[words.length - 1].toLowerCase();
  if (!lastWord) return [];
  return allFields.value.filter(f => f.toLowerCase().includes(lastWord)).slice(0, 8);
});

const selectField = (fieldName: string) => {
  const words = searchText.value.split(/\s+/);
  words[words.length - 1] = `${fieldName}: `;
  searchText.value = words.join(' ');
  showPanel.value = false;
};

// 3. 执行查询
const searchHistoryAlerts = async () => {
  if (!searchText.value.includes(':')) {
    ElMessage.info("请完成查询表达式 (例如 agent.id: 001)");
    return;
  }
  historyLoading.value = true;
  const [field, value] = searchText.value.split(':').map(s => s.trim());
  try {
    const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 300,
      sort: [{ "timestamp": "desc" }],
      query: { match_phrase: { [field]: value } }
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}`, 'Content-Type': 'application/json' }
    });
    historyLogs.value = res.data.hits.hits;
  } catch (err) {
    ElMessage.error("查询失败");
  } finally {
    historyLoading.value = false;
  }
};

// 4. 打开详情弹窗
const openHistoryDetail = (logSource: any) => {
  currentHistoryLog.value = logSource;
  historyDetailVisible.value = true;
};

const getLevelColor = (level: number) => {
  if (level >= 13) return '#f5023d';
  if (level >= 11) return '#e3b337';
  return '#31ABE3';
};

let timer: any = null;
onMounted(() => {
  getWazuhAlerts();
  timer = setInterval(getWazuhAlerts, 20000);
  fetchAvailableFields();
});

onBeforeUnmount(() => {
  if (timer) clearInterval(timer);
});
</script>

<template>
  <div class="tg-root flex flex-col h-full">
    <!-- Tool Bar -->
    <div class="tg-toolbar flex items-center justify-between flex-shrink-0 px-4 py-3">
      <div class="flex items-center gap-1.5">
        <button
          :class="['tab-pill', state.currentTab === 'alarm' ? 'tab-pill--active' : 'tab-pill--inactive']"
          @click="state.currentTab = 'alarm'"
        >
          <span class="tab-dot"></span>
          近期告警
        </button>
        <button
          :class="['tab-pill', state.currentTab === 'history' ? 'tab-pill--active' : 'tab-pill--inactive']"
          @click="state.currentTab = 'history'"
        >
          <span class="tab-dot"></span>
          历史查询
        </button>
      </div>

      <div v-if="state.currentTab === 'alarm'" class="flex items-center gap-1">
        <button
          v-for="t in ['1h', '1d', '7d']"
          :key="t"
          :class="['time-chip', state.selectedTimeRange === t ? 'time-chip--active' : 'time-chip--inactive']"
          @click="changeTimeRange(t)"
        >
          {{ t === '1h' ? '1小时' : t === '1d' ? '24小时' : '一周' }}
        </button>
      </div>
    </div>

    <!-- ── 等级筛选 ── -->
    <div v-if="state.currentTab === 'alarm'" class="level-filter-bar flex items-center gap-1.5 px-4 py-2">
      <span class="level-filter-label">等级筛选</span>
      <button
        v-for="opt in levelOptions"
        :key="opt.key"
        :class="['level-chip', state.selectedLevel === opt.key ? 'level-chip--active' : 'level-chip--inactive']"
        @click="changeLevelFilter(opt.key)"
      >
        {{ opt.label }}
      </button>
    </div>

    <!-- ── Alarm Monitor ── -->
    <template v-if="state.currentTab === 'alarm'">
      <div class="al-list-header grid grid-cols-[1.5fr_0.5fr_1fr_2fr] gap-1 px-4 py-2.5 text-xs font-semibold">
        <span class="text-center">时刻</span>
        <span class="text-center">级别</span>
        <span class="text-center">主机</span>
        <span class="text-center">描述</span>
      </div>

      <div
        :class="[
          'al-list-body flex-1 overflow-y-auto px-4',
          state.selectedTimeRange !== '1h' ? 'al-list-body--manual' : ''
        ]"
      >
        <div
          :class="[
            'al-list-scroll',
            state.alarmData.length > 5 && state.selectedTimeRange === '1h' ? 'al-list-scroll--auto' : ''
          ]"
        >
          <div
            v-for="(item, index) in (state.selectedTimeRange === '1h' ? [...state.alarmData, ...state.alarmData] : state.alarmData)"
            :key="index"
            class="al-row grid grid-cols-[1.5fr_0.5fr_1fr_2fr] gap-1 px-2 py-2.5 rounded-md cursor-pointer transition-all duration-200"
            @click="showDetail(item)"
          >
            <span class="text-center text-xs truncate text-[var(--muted-foreground)] font-mono">
              {{ item.formattedTime }}
            </span>
            <span
              class="text-center text-xs font-bold font-mono"
              :style="{ color: item.rule.level >= 13 ? '#f5023d' : '#e3b337' }"
            >
              L{{ item.rule.level }}
            </span>
            <span class="text-center text-xs truncate text-[var(--foreground)]">{{ item.agent.name }}</span>
            <span class="text-center text-xs truncate text-[var(--muted-foreground)]">{{ item.rule.description }}</span>
          </div>
        </div>
      </div>
    </template>
    <!-- ── Detail Modal ── -->
    <Teleport to="body">
      <div v-if="state.detailVisible" class="modal-mask" @click.self="state.detailVisible = false">
        <div class="modal-panel">
          <div class="modal-header">
            <h3 class="text-sm font-bold text-[#31ABE3] m-0">告警日志详情</h3>
            <div class="flex items-center gap-2">
              <button class="modal-btn modal-btn--copy" @click="copyToClipboard(state.selectedLog.raw)">复制 JSON</button>
              <button class="modal-btn modal-btn--close" @click="state.detailVisible = false">关闭</button>
            </div>
          </div>
          <div class="modal-body">
            <pre class="modal-pre">{{ state.selectedLog.raw }}</pre>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- ── History Query (模块 B) ── -->
    <template v-if="state.currentTab === 'history'">
      <div class="hq-search-area flex gap-2.5 mb-3 px-4 pt-3 flex-shrink-0 relative">
        <div class="hq-search-wrap flex-1 relative">
          <div :class="['hq-input-wrap', showPanel ? 'hq-input-wrap--focus' : '']">
            <span class="hq-search-prefix">🔍</span>
            <input
              v-model="searchText"
              placeholder="输入字段关键词 (如 agent.id: 001)"
              @focus="showPanel = true"
              @keyup.enter="searchHistoryAlerts"
              class="hq-search-input"
            />
            <button v-if="searchText" class="hq-search-clear" @click="searchText = ''">×</button>
          </div>
          <div v-if="showPanel && filteredFields.length > 0" class="hq-dropdown">
            <div v-for="field in filteredFields" :key="field" class="hq-dropdown-item" @mousedown.prevent="selectField(field)">
              <span class="hq-field-icon">f</span> {{ field }}
            </div>
          </div>
        </div>
        <button class="hq-btn-query" @click="searchHistoryAlerts" :disabled="historyLoading">
          {{ historyLoading ? '查询中...' : '查询' }}
        </button>
      </div>

      <div class="hq-list flex-1 overflow-y-auto px-4 pb-4">
        <div v-if="historyLogs.length === 0 && !historyLoading" class="hq-empty">
          等待查询指令，输入字段名并使用冒号指定搜索值
        </div>

        <div
          v-for="item in historyLogs"
          :key="item._id"
          class="hq-card"
          @click="openHistoryDetail(item._source)"
        >
          <div class="hq-card-header">
            <span class="hq-card-time">{{ new Date(item._source.timestamp).toLocaleString() }}</span>
            <span class="hq-card-level" :style="{ color: getLevelColor(item._source.rule?.level) }">
              Level {{ item._source.rule?.level }}
            </span>
          </div>
          <div class="hq-card-body">{{ item._source.rule?.description || item._source.message || '--' }}</div>
          <div class="hq-card-footer">点击查看完整详情</div>
        </div>
      </div>
    </template>

    <!-- ── History Detail Modal ── -->
    <Teleport to="body">
      <div v-if="historyDetailVisible" class="modal-mask" @click.self="historyDetailVisible = false">
        <div class="modal-panel">
          <div class="modal-header">
            <h3 class="text-sm font-bold text-[#31ABE3] m-0">历史告警日志详情</h3>
            <div class="flex items-center gap-2">
              <button class="modal-btn modal-btn--copy" @click="copyToClipboard(JSON.stringify(currentHistoryLog, null, 2))">复制 JSON</button>
              <button class="modal-btn modal-btn--close" @click="historyDetailVisible = false">关闭</button>
            </div>
          </div>
          <div class="modal-body">
            <pre class="modal-pre">{{ JSON.stringify(currentHistoryLog, null, 2) }}</pre>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped lang="scss">
// ── Root ──
.tg-root {
  background: var(--background, #ffffff);
  border-radius: 8px;
  border: 1px solid #e5e7eb;
  position: relative;
  overflow: hidden;
  height: 100%;
}

// ── Toolbar ──
.tg-toolbar {
  border-bottom: 1px solid #e5e7eb;
  background: #f8fafc;
}

.tab-pill {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 5px 14px;
  font-size: 12px;
  font-weight: 500;
  border-radius: 999px;
  cursor: pointer;
  transition: all 0.25s ease;
  border: none;

  .tab-dot {
    width: 5px;
    height: 5px;
    border-radius: 50%;
    transition: all 0.3s ease;
  }

  &--inactive {
    background: transparent;
    color: var(--muted-foreground, #7c8a9e);
    border: 1px solid var(--border, rgba(49, 171, 227, 0.12));
    .tab-dot { background: var(--muted-foreground, #7c8a9e); }
    &:hover {
      color: var(--foreground, #d3d6dd);
      border-color: rgba(49, 171, 227, 0.3);
      background: rgba(49, 171, 227, 0.05);
      .tab-dot { background: #31ABE3; }
    }
  }

  &--active {
    background: rgba(49, 171, 227, 0.1);
    color: #31ABE3;
    border: 1px solid rgba(49, 171, 227, 0.2);
    .tab-dot { background: #31ABE3; box-shadow: 0 0 6px rgba(49, 171, 227, 0.4); }
  }
}

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

// ── Level Filter ──
.level-filter-bar {
  border-bottom: 1px solid #e5e7eb;
  background: #f8fafc;
}

.level-filter-label {
  font-size: 11px;
  color: var(--muted-foreground, #7c8a9e);
  margin-right: 6px;
  white-space: nowrap;
  user-select: none;
}

.level-chip {
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

// ── Alarm List ──
.al-list-header {
  background: #f8fafc;
  color: var(--muted-foreground, #7c8a9e);
  border-bottom: 1px solid #e5e7eb;
}

.al-list-body {
  position: relative;
  overflow: hidden;

  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb { background: color-mix(in oklab, var(--muted-foreground, #7c8a9e) 15%, transparent); border-radius: 2px; }

  &--manual { overflow-y: auto; }
}

.al-list-scroll {
  position: relative;

  &--auto {
    animation: alScrollUp 30s linear infinite;
    &:hover { animation-play-state: paused; }
  }
}

.al-row {
  border-bottom: 1px solid color-mix(in oklab, #e5e7eb 50%, transparent);

  &:hover {
    background: rgba(49, 171, 227, 0.04);
  }

  &:last-child { border-bottom: none; }
}

@keyframes pulse {
  0%, 100% { opacity: 0.2; }
  50% { opacity: 0.4; }
}

// ── Scroll Animation ──
@keyframes alScrollUp {
  0% { transform: translateY(0); }
  100% { transform: translateY(-50%); }
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

// ── History Query (模块 B) ──
.hq-search-area {
  z-index: 10;
}

.hq-search-wrap {
  position: relative;
}

.hq-input-wrap {
  display: flex;
  align-items: center;
  background: #f9fafb;
  border: 1px solid #d1d5db;
  border-radius: 8px;
  padding: 0 12px;
  transition: all 0.2s ease;

  &--focus {
    border-color: rgba(49, 171, 227, 0.3);
    box-shadow: 0 0 0 2px rgba(49, 171, 227, 0.06);
  }
}

.hq-search-prefix {
  color: var(--muted-foreground, #7c8a9e);
  font-size: 13px;
  margin-right: 6px;
  opacity: 0.6;
}

.hq-search-input {
  flex: 1;
  background: transparent;
  border: none;
  padding: 9px 8px;
  color: #1f2937;
  outline: none;
  font-family: ui-monospace, monospace;
  font-size: 12.5px;

  &::placeholder { color: var(--muted-foreground, #7c8a9e); opacity: 0.4; }
}

.hq-search-clear {
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

.hq-dropdown {
  position: absolute;
  top: calc(100% + 4px);
  left: 0;
  width: 100%;
  background: var(--popover, #ffffff);
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  z-index: 100;
  max-height: 220px;
  overflow-y: auto;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);

  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb { background: color-mix(in oklab, var(--muted-foreground, #7c8a9e) 15%, transparent); border-radius: 2px; }
}

.hq-dropdown-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 9px 14px;
  cursor: pointer;
  border-bottom: 1px solid rgba(0, 0, 0, 0.05);
  font-size: 12.5px;
  font-family: ui-monospace, monospace;
  color: var(--foreground, #1f2937);
  transition: background 0.15s ease;

  &:hover { background: rgba(49, 171, 227, 0.06); }
  &:last-child { border-bottom: none; }

  .hq-field-icon {
    color: #31ABE3;
    font-weight: bold;
    font-size: 11px;
    flex-shrink: 0;
  }
}

.hq-btn-query {
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

  &:hover:not(:disabled) {
    background: rgba(49, 171, 227, 0.18);
    border-color: rgba(49, 171, 227, 0.3);
  }

  &:disabled { opacity: 0.5; cursor: not-allowed; }
}

.hq-list {
  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb { background: color-mix(in oklab, var(--muted-foreground, #7c8a9e) 15%, transparent); border-radius: 2px; }
}

.hq-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  font-size: 12px;
  color: var(--muted-foreground, #7c8a9e);
  opacity: 0.5;
  text-align: center;
  padding: 40px 20px;
}

.hq-card {
  background: var(--card, #ffffff);
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  padding: 12px 14px;
  margin-bottom: 10px;
  cursor: pointer;
  transition: all 0.2s ease;
  border-left: 3px solid #31ABE3;

  &:hover {
    border-color: color-mix(in oklab, #e5e7eb 60%, #31ABE3);
    background: #f8fafc;
    transform: translateX(2px);
  }
}

.hq-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 6px;

  .hq-card-time {
    font-family: ui-monospace, monospace;
    font-size: 13px;
    color: var(--muted-foreground, #7c8a9e);
  }

  .hq-card-level {
    font-size: 11px;
    font-weight: 700;
    font-family: ui-monospace, monospace;
  }
}

.hq-card-body {
  font-size: 13px;
  color: var(--foreground, #1f2937);
  line-height: 1.5;
  word-break: break-all;
}

.hq-card-footer {
  font-size: 10px;
  color: #31ABE3;
  margin-top: 8px;
  text-align: right;
  opacity: 0.7;
}
</style>
