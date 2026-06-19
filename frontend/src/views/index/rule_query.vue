<script setup lang="ts">
import { ref, computed, onMounted } from "vue";
import { ElMessage } from "element-plus";
import axios from 'axios';

// ── Wazuh 认证配置 ──
const wazuhUser = import.meta.env.VITE_WAZUH_SERVER_API_USERNAME;
const wazuhPass = import.meta.env.VITE_WAZUH_SERVER_API_PASSWORD;
const AUTH_PAYLOAD = btoa(`${wazuhUser}:${wazuhPass}`);
const token = ref("");

const searchText = ref("");
const rules = ref<any[]>([]);
const loading = ref(false);
const detailVisible = ref(false);

const currentRule = ref<any>(null);
const currentRuleXml = ref("");

const showPanel = ref(false);
const searchStage = ref<'field' | 'operator' | 'value'>('field');
const selectedField = ref("");
const selectedOperator = ref("");

const fieldOptions = [
  { label: 'id', display: 'id', desc: 'Rule ID', color: '#e06c75' },
  { label: 'level', display: 'level', desc: 'Severity level', color: '#d19a66' },
  { label: 'groups', display: 'group', desc: 'Rule group', color: '#c678dd' },
  { label: 'filename', display: 'file', desc: 'XML Filename', color: '#98c379' }
];

const operators = [{ label: '=', desc: 'equality' }, { label: '>', desc: 'gt' }, { label: '<', desc: 'lt' }];

const valueSuggestions = computed(() => {
  const field = selectedField.value;
  if (selectedField.value === 'level') return ['3', '5', '10', '15'];
  if (field === 'id') return ['100', '500', '1000', '2501', '92145'];
  return ['sysmon', 'windows', 'sshd'];
});

// ── 核心方法 ──
const authenticate = async () => {
  try {
    const res = await axios.get('/wazuh-api/security/user/authenticate', {
      headers: { 'Authorization': `Basic ${AUTH_PAYLOAD}` }
    });
    token.value = res.data.data.token;
    return true;
  } catch (err) {
    ElMessage.error("Wazuh 认证失败");
    return false;
  }
};

const fetchRules = async (isRetry = false) => {
  if (!token.value) {
    const success = await authenticate();
    if (!success) return;
  }

  loading.value = true;
  const hasLogic = /(=|>|<)/.test(searchText.value);
  const params: any = { limit: 50, sort: '-level' };
  if (hasLogic) params.q = searchText.value;
  else if (searchText.value.trim()) params.search = searchText.value;

  try {
    const res = await axios.get('/wazuh-api/rules', {
      params,
      headers: { 'Authorization': `Bearer ${token.value}` }
    });
    rules.value = res.data.data?.affected_items || [];
  } catch (err: any) {
    if (err.response?.status === 401 && !isRetry) {
      token.value = "";
      await fetchRules(true);
    } else {
      ElMessage.error("获取列表失败");
    }
  } finally {
    loading.value = false;
  }
};

const fetchRuleXml = async (rule: any) => {
  loading.value = true;
  currentRule.value = rule;
  currentRuleXml.value = "";

  try {
    const res = await axios.get(`/wazuh-api/rules/files/${rule.filename}`, {
      headers: {
        'Authorization': `Bearer ${token.value}`,
        'Accept': 'application/xml, text/plain'
      }
    });

    if (typeof res.data === 'string' && !res.data.trim().startsWith('{')) {
      currentRuleXml.value = res.data;
    } else {
      const jsonData = typeof res.data === 'string' ? JSON.parse(res.data) : res.data;
      const content = jsonData.data?.affected_items?.[0];
      if (content) {
        currentRuleXml.value = jsonToXml(content);
      }
    }
    detailVisible.value = true;
  } catch (err: any) {
    console.error("XML获取失败:", err);
    ElMessage.error("获取规则内容失败");
  } finally {
    loading.value = false;
  }
};

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

const handleSelect = (item: any) => {
  if (searchStage.value === 'field') {
    selectedField.value = item.label;
    searchText.value = item.label;
    searchStage.value = 'operator';
  } else if (searchStage.value === 'operator') {
    selectedOperator.value = item.label;
    searchText.value = `${selectedField.value}${item.label}`;
    searchStage.value = 'value';
  } else if (searchStage.value === 'value') {
    searchText.value = `${selectedField.value}${selectedOperator.value}${item}`;
    showPanel.value = false;
    searchStage.value = 'field';
    fetchRules();
  }
};

const getLevelColor = (level: any) => {
  const l = Number(level);
  if (l >= 12) return '#f5023d';
  if (l >= 8) return '#e3b337';
  return '#31ABE3';
};

onMounted(() => {
  fetchRules();
});
</script>

<template>
  <div class="rq-root flex flex-col h-full">
    <!-- Tool Bar -->
    <div class="rq-toolbar flex items-center flex-shrink-0 px-4 py-3">
      <div class="flex items-center gap-1.5">
        <span class="toolbar-badge">📜 Wazuh 规则查询</span>
        <span class="toolbar-hint">检索与浏览安全规则库</span>
      </div>
    </div>

    <div class="rq-body flex-1 overflow-hidden px-4 pb-4">
      <div class="h-full flex flex-col" v-loading="loading" element-loading-background="rgba(0, 0, 0, 0.5)">
        <!-- Search area -->
        <div class="search-area flex gap-2.5 mb-3 relative flex-shrink-0">
          <div class="search-wrap flex-1 relative">
            <div :class="['search-input-wrap', showPanel ? 'search-input-wrap--focus' : '']">
              <span class="search-prefix">🔍</span>
              <input
                v-model="searchText"
                placeholder="输入查询 (如 level>10) 或使用下拉构造..."
                @focus="showPanel = true"
                @keyup.enter="fetchRules()"
                class="search-input"
              />
              <button v-if="searchText" class="search-clear" @click="searchText=''; searchStage='field'">×</button>
            </div>

            <!-- Interactive query builder -->
            <div v-if="showPanel" class="query-panel">
              <div v-if="searchStage === 'field'">
                <div class="query-row query-row--action" @click="showPanel=false; fetchRules()">
                  <strong>Search</strong><span>执行当前查询</span>
                </div>
                <div v-for="f in fieldOptions" :key="f.label" class="query-row" @click="handleSelect(f)">
                  <b :style="{color: f.color}">⊚ {{ f.display }}</b>
                  <span>{{ f.desc }}</span>
                </div>
              </div>
              <div v-else-if="searchStage === 'operator'">
                <div v-for="op in operators" :key="op.label" class="query-row" @click="handleSelect(op)">
                  <b>{{ op.label }}</b><span>{{ op.desc }}</span>
                </div>
              </div>
              <div v-else-if="searchStage === 'value'">
                <div v-for="v in valueSuggestions" :key="v" class="query-row" @click="handleSelect(v)">
                  <b>{{ v }}</b><span>建议值</span>
                </div>
              </div>
            </div>
          </div>
          <button class="btn-refresh flex-shrink-0" @click="fetchRules(false)">刷新</button>
        </div>

        <!-- Rule list -->
        <div class="rule-list flex-1 overflow-y-auto">
          <div v-if="rules.length === 0 && !loading" class="flex items-center justify-center h-32 text-sm text-[var(--muted-foreground)] opacity-50">
            未查询到匹配的安全规则数据。
          </div>
          <div
            v-for="rule in rules"
            :key="rule.id"
            class="rule-card"
            @click="fetchRuleXml(rule)"
          >
            <div class="rule-card-header">
              <span class="rule-id">ID: {{ rule.id }}</span>
              <span class="rule-level" :style="{ color: getLevelColor(rule.level) }">
                Level {{ rule.level }}
              </span>
            </div>
            <p class="rule-desc">{{ rule.description }}</p>
            <div class="rule-file">{{ rule.filename }}</div>
          </div>
        </div>
      </div>
    </div>

    <!-- ── XML Detail Dialog ── -->
    <el-dialog
      v-model="detailVisible"
      :title="`规则源码: ${currentRule?.filename}`"
      width="75%"
      destroy-on-close
      append-to-body
      class="xml-dialog"
    >
      <div class="xml-viewer">
        <div class="xml-path">Path: {{ currentRule?.relative_dirname }}/{{ currentRule?.filename }}</div>
        <pre class="xml-content">{{ currentRuleXml }}</pre>
      </div>
      <template #footer>
        <button class="btn-close-dialog" @click="detailVisible = false">关闭预览</button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped lang="scss">
// ── Root ──
.rq-root {
  background: #ffffff;
  border-radius: 8px;
  border: 1px solid #e5e7eb;
  position: relative;
  overflow: hidden;
  height: 100%;
}

// ── Toolbar ──
.rq-toolbar {
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

// ── Body ──
.rq-body {
  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb { background: color-mix(in oklab, var(--muted-foreground, #7c8a9e) 15%, transparent); border-radius: 2px; }
}

// ── Search ──
.search-area {
  z-index: 10;
}

.search-wrap {
  position: relative;
}

.search-input-wrap {
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

.search-prefix {
  color: var(--muted-foreground, #7c8a9e);
  font-size: 13px;
  margin-right: 6px;
  opacity: 0.6;
}

.search-input {
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

.search-clear {
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

// ── Query Builder ──
.query-panel {
  position: absolute;
  top: calc(100% + 4px);
  left: 0;
  width: 100%;
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  z-index: 100;
  max-height: 220px;
  overflow-y: auto;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);

  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb { background: color-mix(in oklab, var(--muted-foreground, #7c8a9e) 15%, transparent); border-radius: 2px; }
}

.query-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 9px 14px;
  cursor: pointer;
  border-bottom: 1px solid rgba(0, 0, 0, 0.05);
  font-size: 12.5px;
  transition: background 0.15s ease;

  &:hover { background: rgba(49, 171, 227, 0.06); }
  &:last-child { border-bottom: none; }

  b { font-family: ui-monospace, monospace; }
  span { color: var(--muted-foreground, #7c8a9e); font-size: 11px; }

  &--action {
    background: rgba(29, 78, 216, 0.03);
    color: #1d4ed8;
    border-bottom: 1px solid rgba(29, 78, 216, 0.1);
    font-weight: 500;
  }
}

.btn-refresh {
  background: rgba(49, 171, 227, 0.1);
  border: 1px solid #e5e7eb;
  color: #31ABE3;
  padding: 0 16px;
  font-size: 12px;
  font-weight: 600;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;

  &:hover {
    background: rgba(49, 171, 227, 0.18);
    border-color: rgba(49, 171, 227, 0.3);
  }
}

// ── Rule List ──
.rule-list {
  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb { background: color-mix(in oklab, var(--muted-foreground, #7c8a9e) 15%, transparent); border-radius: 2px; }
}

.rule-card {
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  padding: 12px 14px;
  margin-bottom: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
  border-left: 3px solid #31ABE3;

  &:hover {
    border-color: color-mix(in oklab, #e5e7eb 60%, #31ABE3);
    background: #f8fafc;
    transform: translateX(2px);
  }
}

.rule-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 4px;

  .rule-id {
    font-family: ui-monospace, monospace;
    font-size: 12.5px;
    font-weight: 700;
    color: #1d4ed8;
  }

  .rule-level {
    font-size: 11px;
    font-weight: 700;
    font-family: ui-monospace, monospace;
  }
}

.rule-desc {
  font-size: 12.5px;
  color: #374151;
  line-height: 1.45;
  margin: 4px 0;
  word-break: break-all;
}

.rule-file {
  font-size: 10.5px;
  color: var(--muted-foreground, #7c8a9e);
  text-align: right;
  font-style: italic;
  font-family: ui-monospace, monospace;
  opacity: 0.6;
}

// ── XML Dialog ──
.xml-viewer {
  background: #ffffff;
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid #e5e7eb;
}

.xml-path {
  background: #ffffff;
  padding: 9px 16px;
  font-size: 13px;
  color: #374151;
  font-family: ui-monospace, monospace;
  border-bottom: 1px solid #e5e7eb;
}

.xml-content {
  margin: 0;
  padding: 16px 20px;
  color: #1f2937;
  font-family: 'Consolas', 'Monaco', ui-monospace, monospace;
  font-size: 14px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 55vh;
  overflow-y: auto;

  &::-webkit-scrollbar { width: 4px; }
  &::-webkit-scrollbar-thumb { background: color-mix(in oklab, var(--muted-foreground, #7c8a9e) 15%, transparent); border-radius: 2px; }
}

.btn-close-dialog {
  background: #f3f4f6;
  border: 1px solid #d1d5db;
  color: #374151;
  padding: 7px 20px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 12px;
  transition: all 0.2s ease;

  &:hover {
    background: var(--accent, #1e2d45);
    border-color: rgba(49, 171, 227, 0.3);
  }
}

// ── Element Dialog Overrides ──
:deep(.xml-dialog) {
  --el-dialog-bg-color: #ffffff !important;

  .el-dialog {
    background: #ffffff !important;
    border: 1px solid #e5e7eb;
    border-radius: 10px;
    box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);
  }

  .el-dialog__title {
    color: #1d4ed8;
    font-weight: 700;
    font-size: 14.5px;
  }

  .el-dialog__header {
    border-bottom: 1px solid #e5e7eb;
    margin-right: 0;
    padding: 14px 20px;
  }

  .el-dialog__body { padding: 16px 20px; }

  .el-dialog__footer {
    border-top: 1px solid #e5e7eb;
    padding: 12px 20px;
  }

  .el-dialog__headerbtn .el-dialog__close { color: var(--muted-foreground, #7c8a9e); &:hover { color: var(--foreground); } }
}
</style>
