<script setup lang="ts">
import { ref, reactive, computed, onMounted, onBeforeUnmount } from "vue";
import { ElMessage } from "element-plus";
import axios from 'axios';

// ─────────────────────────────────────────────────────────────────────────
// 1. 认证配置（融合 Indexer 和 Wazuh API 两套凭证）
// ─────────────────────────────────────────────────────────────────────────
// A. Indexer 凭证（查日志）
const indexerUser = import.meta.env.VITE_WAZUH_INDEXER_USER;
const indexerPass = import.meta.env.VITE_WAZUH_INDEXER_PASSWORD;
const INDEXER_AUTH = btoa(`${indexerUser}:${indexerPass}`);

// B. Wazuh API 凭证（查规则定义）
const wazuhUser = import.meta.env.VITE_WAZUH_SERVER_API_USERNAME;
const wazuhPass = import.meta.env.VITE_WAZUH_SERVER_API_PASSWORD;
const AUTH_PAYLOAD = btoa(`${wazuhUser}:${wazuhPass}`);
const token = ref("");

// Wazuh API 认证方法
const authenticateWazuhApi = async () => {
  try {
    const res = await axios.get('/wazuh-api/security/user/authenticate', {
      headers: { 'Authorization': `Basic ${AUTH_PAYLOAD}` }
    });
    token.value = res.data.data.token;
    return true;
  } catch (err) {
    ElMessage.error("Wazuh API 认证失败，将无法查看规则 XML 明细");
    return false;
  }
};

// ─────────────────────────────────────────────────────────────────────────
// 2. 状态管理（承袭自你的日志模块 A）
// ─────────────────────────────────────────────────────────────────────────
const state = reactive({
  alarmData: [] as any[],
  loading: false,
  selectedTimeRange: '1h',
  selectedLevel: 'all',
  
  // 分页状态（与你之前的进程组件规范对齐）
  pageSize: 15,
  currentPage: 1,
});

// 告警等级筛选配置
const levelOptions = [
  { key: 'all', label: '全部等级', range: null },
  { key: '10-11', label: '低危 10-11', range: { gte: 10, lte: 11 } },
  { key: '12-13', label: '中危 12-13', range: { gte: 12, lte: 13 } },
  { key: '14-15', label: '高危 14-15', range: { gte: 14, lte: 15 } },
];

// 时间戳格式化
const formatDateTime = (timestamp: string) => {
  return new Date(timestamp).toLocaleString();
};

// 颜色映射逻辑
const getLevelColor = (level: number) => {
  if (level >= 13) return '#f5023d';
  if (level >= 11) return '#e3b337';
  return '#31ABE3';
};

// 纯前端分页计算
const tableData = computed(() => {
  const start = (state.currentPage - 1) * state.pageSize;
  const end = start + state.pageSize;
  return state.alarmData.slice(start, end);
});
const totalItems = computed(() => state.alarmData.length);

// ─────────────────────────────────────────────────────────────────────────
// 3. 核心方法：从 Indexer 获取告警日志（解决 404）
// ─────────────────────────────────────────────────────────────────────────
const getWazuhAlerts = async () => {
  state.loading = true;
  try {
    const timeMap: Record<string, string> = { '1h': 'now-1h', '1d': 'now-1d', '7d': 'now-7d' };
    const levelOpt = levelOptions.find(o => o.key === state.selectedLevel);
    
    // 默认展示 >= 3 级的全部日志以匹配你截图的低等级状态，如果没有筛选则放开限制
    const levelCondition = levelOpt?.range
      ? { range: { "rule.level": { ...levelOpt.range } } }
      : { range: { "rule.level": { "gte": 1 } } }; 

    const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 10000, // 拉取较大数据量以供前端分页
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
    ElMessage.error("从 Indexer 获取日志失败");
  } finally {
    state.loading = false;
  }
};

// 筛选变更拦截
const changeTimeRange = (range: string) => {
  state.selectedTimeRange = range;
  state.currentPage = 1;
  getWazuhAlerts();
};

const changeLevelFilter = (level: string) => {
  state.selectedLevel = level;
  state.currentPage = 1;
  getWazuhAlerts();
};

// ─────────────────────────────────────────────────────────────────────────
// 4. 🎯 核心联动模块：点击 Rule ID 从 Wazuh API 联动规则 XML
// ─────────────────────────────────────────────────────────────────────────
const detailVisible = ref(false);      // 控制右侧 Drawer 抽屉可见性
const currentRule = ref<any>(null);    // 存储当前规则的元数据
const currentRuleXml = ref("");        // 存储转换后的 XML 字符串
const drawerLoading = ref(false);      // 抽屉内部加载状态

// 根据点击的 Rule ID 去 Wazuh 管理端找背后的 XML 文件
const handleRuleIdClick = async (ruleId: string) => {
  if (!ruleId) return;
  
  detailVisible.value = true;
  drawerLoading.value = true;
  currentRuleXml.value = "";
  currentRule.value = null;

  // 检查并获取 Wazuh API 的 Token
  if (!token.value) {
    const success = await authenticateWazuhApi();
    if (!success) { drawerLoading.value = false; return; }
  }

  try {
    // Step 1: 先通过 Rule ID 查到它属于哪个规则文件 (filename)
    const ruleRes = await axios.get('/wazuh-api/rules', {
      params: { q: `id=${ruleId}` },
      headers: { 'Authorization': `Bearer ${token.value}` }
    });
    
    const ruleInfo = ruleRes.data.data?.affected_items?.[0];
    if (!ruleInfo) {
      throw new Error("Wazuh 未找到该规则的注册信息");
    }
    currentRule.value = ruleInfo;

    // Step 2: 通过 filename 请求对应的具体内容
    const xmlRes = await axios.get(`/wazuh-api/rules/files/${ruleInfo.filename}`, {
      headers: {
        'Authorization': `Bearer ${token.value}`,
        'Accept': 'application/xml, text/plain'
      }
    });

    // Step 3: XML 解析与转义还原处理（承袭自你的规则模块）
    if (typeof xmlRes.data === 'string' && !xmlRes.data.trim().startsWith('{')) {
      currentRuleXml.value = xmlRes.data;
    } else {
      const jsonData = typeof xmlRes.data === 'string' ? JSON.parse(xmlRes.data) : xmlRes.data;
      const content = jsonData.data?.affected_items?.[0];
      if (content) {
        currentRuleXml.value = jsonToXml(content);
      }
    }
  } catch (err: any) {
    console.error("联动获取规则详情失败:", err);
    currentRuleXml.value = ``;
  } finally {
    drawerLoading.value = false;
  }
};

// JSON 转 XML 辅助工具函数（完全保留你的实现逻辑）
const jsonToXml = (obj: any) => {
  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
  const ensureArray = (item: any) => {
    if (!item) return [];
    return Array.isArray(item) ? item : [item];
  };

  ensureArray(obj.var).forEach((v: any) => {
    xml += `<var name="${v['@name']}">${v['#text'] || ''}</var>\n`;
  });

  ensureArray(obj.group).forEach((g: any) => {
    xml += `<group name="${g['@name']}">\n`;
    ensureArray(g.rule).forEach((r: any) => {
      xml += `  <rule id="${r['@id']}" level="${r['@level']}">\n`;
      Object.keys(r).forEach(key => {
        if (key.startsWith('@')) return;
        const value = r[key];
        ensureArray(value).forEach(val => {
          if (typeof val === 'object') {
            const attr = val['@name'] ? ` name="${val['@name']}"` : '';
            xml += `    <${key}${attr}>${val['#text'] || ''}</${key}>\n`;
          } else {
            xml += `    <${key}>${val}</${key}>\n`;
          }
        });
      });
      xml += `  </rule>\n`;
    });
    xml += `</group>\n\n`;
  });
  return xml;
};

// ─────────────────────────────────────────────────────────────────────────
// 5. 分页辅助事件
// ─────────────────────────────────────────────────────────────────────────
const handleSizeChange = (val: number) => {
  state.pageSize = val;
  state.currentPage = 1;
};
const handleCurrentChange = (val: number) => {
  state.currentPage = val;
};

// 生命周期挂载
let timer: any = null;
onMounted(() => {
  getWazuhAlerts();
  timer = setInterval(getWazuhAlerts, 20000); // 20秒自动刷新
});

onBeforeUnmount(() => {
  if (timer) clearInterval(timer);
});
</script>

<template>
  <div class="tg-root flex flex-col h-full">
    <div class="tg-toolbar flex items-center justify-between flex-shrink-0 px-4 py-3">
      <div class="flex items-center gap-4">
        <span class="text-sm font-bold text-[#31ABE3]">🛡️ 实时告警日志联动</span>
        
        <div class="filter-group">
          <button 
            v-for="t in ['1h', '1d', '7d']" :key="t"
            class="filter-btn" :class="{ active: state.selectedTimeRange === t }"
            @click="changeTimeRange(t)"
          >{{ t }}</button>
        </div>

        <select 
          class="level-select" 
          :value="state.selectedLevel" 
          @change="changeLevelFilter(($event.target as HTMLSelectElement).value)"
        >
          <option v-for="opt in levelOptions" :key="opt.key" :value="opt.key">
            {{ opt.label }}
          </option>
        </select>
      </div>

      <div class="flex items-center gap-2">
        <button class="refresh-btn" @click="getWazuhAlerts" :disabled="state.loading">🔄 强制刷新</button>
        <span class="text-xs text-[#7c8a9e]">命中安全告警: {{ totalItems }} 条</span>
      </div>
    </div>

    <div
      v-if="totalItems > 0"
      class="al-list-header grid grid-cols-[2fr_1.2fr_4fr_0.8fr_1fr] gap-2 px-4 py-2.5 text-xs font-semibold flex-shrink-0"
    >
      <span>timestamp</span>
      <span>agent.name</span>
      <span>rule.description</span>
      <span>rule.level</span>
      <span>rule.id</span>
    </div>

    <div
      class="al-list-body flex-1 overflow-y-auto px-4"
      v-loading="state.loading"
      element-loading-background="rgba(255, 255, 255, 0.6)"
    >
      <div v-if="totalItems === 0 && !state.loading" class="hq-empty">
        当前过滤条件下未监测到任何威胁告警日志
      </div>

      <div class="al-list-scroll">
        <div
          v-for="(log, index) in tableData"
          :key="index"
          class="al-row grid grid-cols-[2fr_1.2fr_4fr_0.8fr_1fr] gap-2 px-2 py-2 rounded-md transition-all duration-200"
        >
          <span class="text-xs font-mono text-[#64748b] truncate">{{ log.formattedTime }}</span>
          
          <span class="text-xs font-bold text-[#31ABE3] truncate font-mono">
            {{ log.agent?.name || 'Wazuh-Manager' }}
          </span>
          
          <span class="text-xs text-[#334155] truncate" :title="log.rule?.description">
            {{ log.rule?.description || '-' }}
          </span>
          
          <span class="text-xs font-mono font-bold" :style="{ color: getLevelColor(Number(log.rule?.level)) }">
            {{ log.rule?.level || 0 }}
          </span>
          
          <span class="text-xs font-mono">
            <span class="rule-id-link" @click="handleRuleIdClick(log.rule?.id)">
              🔗 {{ log.rule?.id || '-' }}
            </span>
          </span>
        </div>
      </div>
    </div>

    <div class="pagination-bar flex-shrink-0">
      <span class="pagination-info">共查询到 {{ totalItems }} 条明细</span>
      <div class="pagination-controls">
        <div class="page-size-group">
          <span>Rows per page:</span>
          <select
            :value="state.pageSize"
            @change="handleSizeChange(Number(($event as any).target.value))"
            class="page-size-select"
          >
            <option :value="15">15</option>
            <option :value="30">30</option>
            <option :value="50">50</option>
          </select>
        </div>
        <div class="page-nav-group">
          <button class="pg-btn" :disabled="state.currentPage <= 1" @click="handleCurrentChange(state.currentPage - 1)">‹</button>
          <span class="page-info font-mono">{{ state.currentPage }} / {{ Math.ceil(totalItems / state.pageSize) || 1 }}</span>
          <button class="pg-btn" :disabled="state.currentPage >= Math.ceil(totalItems / state.pageSize)" @click="handleCurrentChange(state.currentPage + 1)">›</button>
        </div>
      </div>
    </div>

    <el-drawer
      v-model="detailVisible"
      direction="rtl"
      size="45%"
      custom-class="wazuh-detail-drawer"
      destroy-on-close
    >
      <template #header>
        <div class="drawer-custom-header">
          <span class="title">📋 规则定义明细</span>
          <span class="subtitle" v-if="currentRule">ID: {{ currentRule.id }} | 文件: {{ currentRule.filename }}</span>
        </div>
      </template>

      <div class="drawer-container" v-loading="drawerLoading" element-loading-text="正在越权同步规则库定义...">
        <div v-if="currentRule" class="meta-section grid grid-cols-2 gap-2 mb-4 p-3 rounded bg-[#f8fafc]">
          <div class="text-xs"><strong>严重级别：</strong> 
            <span class="font-bold" :style="{ color: getLevelColor(currentRule.level) }">Level {{ currentRule.level }}</span>
          </div>
          <div class="text-xs truncate"><strong>规则归属组：</strong> {{ currentRule.groups?.join(', ') || '无' }}</div>
        </div>

        <div class="xml-box">
          <div class="xml-header-bar">Wazuh Ruleset Source (XML)</div>
          <pre class="xml-pre"><code>{{ currentRuleXml }}</code></pre>
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<style scoped lang="scss">
.tg-root {
  background: #ffffff;
  border-radius: 8px;
  border: 1px solid #e5e7eb;
  height: 100%;
}
.tg-toolbar {
  border-bottom: 1px solid #e5e7eb;
  background: #f8fafc;
}

/* 时间切换按钮样式 */
.filter-group {
  display: flex;
  background: #f1f5f9;
  padding: 2px;
  border-radius: 6px;
  .filter-btn {
    border: none;
    background: transparent;
    font-size: 11px;
    padding: 3px 10px;
    border-radius: 4px;
    cursor: pointer;
    color: #64748b;
    &.active {
      background: #ffffff;
      color: #31ABE3;
      font-weight: bold;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
  }
}

/* 下拉菜单 */
.level-select {
  background: #ffffff;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  padding: 3px 8px;
  font-size: 11px;
  color: #374151;
  outline: none;
}

.refresh-btn {
  background: #ffffff;
  border: 1px solid #d1d5db;
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 11px;
  color: #374151;
  cursor: pointer;
  &:hover {
    border-color: #31ABE3;
    color: #31ABE3;
  }
}

.al-list-header {
  background: #f8fafc;
  color: #7c8a9e;
  border-bottom: 1px solid #e5e7eb;
}
.al-list-body {
  position: relative;
}
.al-row {
  border-bottom: 1px solid rgba(229, 231, 235, 0.5);
  min-height: 38px;
  align-items: center;
  &:hover { background: rgba(49, 171, 227, 0.03); }
}

/* 🎯 关键：规则 ID 样式转换成高亮超链接 */
.rule-id-link {
  color: #31ABE3;
  font-weight: bold;
  cursor: pointer;
  text-decoration: none;
  padding: 2px 6px;
  background: rgba(49, 171, 227, 0.05);
  border-radius: 4px;
  border: 1px solid rgba(49, 171, 227, 0.15);
  display: inline-block;
  
  &:hover {
    background: #31ABE3;
    color: #ffffff;
    text-decoration: underline;
  }
}

.hq-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  font-size: 12px;
  color: #7c8a9e;
  padding: 40px;
}

/* 分页 */
.pagination-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 16px;
  border-top: 1px solid #e5e7eb;
  background: #f8fafc;
  font-size: 12px;
}
.pagination-controls { display: flex; align-items: center; gap: 16px; color: #7c8a9e; }
.page-size-group { display: flex; align-items: center; gap: 6px; }
.page-size-select { background: #ffffff; border: 1px solid #d1d5db; border-radius: 6px; padding: 2px 6px; }
.page-nav-group { display: flex; align-items: center; gap: 4px; }
.pg-btn { border: 1px solid rgba(49, 171, 227, 0.15); background: transparent; border-radius: 4px; min-width: 24px; cursor: pointer; &:disabled { opacity: 0.4; } }

/* 抽屉样式覆盖 */
:deep(.wazuh-detail-drawer) {
  .el-drawer__header {
    background: #f8fafc;
    border-bottom: 1px solid #e5e7eb;
    margin-bottom: 0;
    padding: 12px 20px;
  }
}
.drawer-custom-header {
  display: flex;
  flex-direction: column;
  .title { font-size: 14px; font-weight: bold; color: #1e293b; }
  .subtitle { font-size: 11px; color: #64748b; font-family: monospace; margin-top: 2px; }
}
.drawer-container {
  padding: 20px;
  height: 100%;
  display: flex;
  flex-direction: column;
}

/* XML 核心视图区 */
.xml-box {
  flex: 1;
  border: 1px solid #cbd5e1;
  border-radius: 6px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  
  .xml-header-bar {
    background: #f1f5f9;
    border-bottom: 1px solid #cbd5e1;
    padding: 6px 12px;
    font-size: 11px;
    font-weight: bold;
    color: #475569;
  }
  .xml-pre {
    margin: 0;
    padding: 12px;
    background: #1e1e1e; /* 换成黑客暗色主题，看 XML 定义更爽 */
    color: #a9b7c6;
    font-family: 'Courier New', monospace;
    font-size: 12px;
    overflow: auto;
    flex: 1;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.5;
  }
}
</style>