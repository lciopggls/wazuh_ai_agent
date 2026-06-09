<script setup lang="ts">
import { ref, computed, onMounted, watch } from "vue";
import { ElMessage } from "element-plus";
import axios from 'axios';

// --- 父组件传入的槽位参数 ---
const props = defineProps<{
  allSessions?: Record<string, any[]>;
  agentId?: string;
  // 💡 新增：接收从会话流中提取出来的 SVG 资源对象
  svgs?: {
    svgChart: string | null;
    attackGraph: string | null;
  }
}>();

// --- 标签页切换状态 ---
const activeTab = ref<'rules' | 'resources'>('rules');

// ==========================================
// --- 核心状态与配置（规则查询功能） ---
// ==========================================
const wazuhUser = import.meta.env.VITE_WAZUH_SERVER_API_USERNAME;
const wazuhPass = import.meta.env.VITE_WAZUH_SERVER_API_PASSWORD;
const AUTH_PAYLOAD = btoa(`${wazuhUser}:${wazuhPass}`);
const token = ref("");

const searchText = ref("");
const rules = ref<any[]>([]);
const loading = ref(false);
const detailVisible = ref(false);

const currentRule = ref<any>(null);      // 存储当前选中的规则 JSON 信息
const currentRuleXml = ref("");          // 存储从 API 获取的原始 XML 字符串

const showPanel = ref(false);
const searchStage = ref<'field' | 'operator' | 'value'>('field');
const selectedField = ref("");
const selectedOperator = ref("");

// 💡 新增：“分析资源”专属弹窗控制状态
const isSvgModalOpen = ref(false);
const svgModalTitle = ref('');
const currentSvgContent = ref('');

// 字段映射选项
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

// --- 规则查询核心方法 ---
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

// 💡 新增：打开 SVG 大图弹窗预览
const openSvgPreview = (title: string, svgRaw: string | null | undefined) => {
  if (!svgRaw) return;
  svgModalTitle.value = title;
  currentSvgContent.value = svgRaw;
  isSvgModalOpen.value = true;
};

// 监听标签页切换
watch(activeTab, (newTab) => {
  if (newTab === 'rules' && rules.value.length === 0) {
    fetchRules();
  }
});

onMounted(() => {
  if (activeTab.value === 'rules') {
    fetchRules();
  }
});
</script>

<template>
  <div class="ai_chat_container">
    <div class="top_bar">
      <div class="agent_tabs">
        <div 
          :class="['tab_item', activeTab === 'rules' ? 'active' : '']"
          @click="activeTab = 'rules'"
        >
          规则查询
        </div>
        <div 
          :class="['tab_item', activeTab === 'resources' ? 'active' : '']"
          @click="activeTab = 'resources'"
        >
          分析资源
        </div>
      </div>
    </div>

    <div class="chat_window">
      <div v-if="activeTab === 'rules'" class="page_pane" v-loading="loading" element-loading-background="rgba(0, 0, 0, 0.5)">
        <div class="search_group">
          <div class="input_container">
            <div class="input_wrapper" :class="{ 'focus': showPanel }">
              <span class="prefix">🔍</span>
              <input 
                v-model="searchText" 
                placeholder="输入查询 (如 level>10) 或使用下拉构造..."
                @focus="showPanel = true"
                @keyup.enter="fetchRules()"
              />
              <button v-if="searchText" class="clear" @click="searchText=''; searchStage='field'">×</button>
            </div>

            <div class="show_panel_box" v-if="showPanel">
              <div v-if="searchStage === 'field'" class="interactive_panel">
                <div class="p_item action" @click="showPanel=false; fetchRules()"><strong>Search</strong><span>执行当前查询</span></div>
                <div v-for="f in fieldOptions" :key="f.label" class="p_item" @click="handleSelect(f)">
                  <b :style="{color: f.color}">⊚ {{ f.display }}</b> <span>{{ f.desc }}</span>
                </div>
              </div>

              <div v-else-if="searchStage === 'operator'" class="interactive_panel">
                <div v-for="op in operators" :key="op.label" class="p_item" @click="handleSelect(op)">
                  <b>{{ op.label }}</b> <span>{{ op.desc }}</span>
                </div>
              </div>

              <div v-else-if="searchStage === 'value'" class="interactive_panel">
                <div v-for="v in valueSuggestions" :key="v" class="p_item" @click="handleSelect(v)">
                  <b>{{ v }}</b> <span>建议值</span>
                </div>
              </div>
            </div>
          </div>
          <button class="refresh_btn" @click="fetchRules(false)">刷新</button>
        </div>

        <div class="rule_list_box">
          <div v-if="rules.length === 0 && !loading" class="empty_box">
            未查询到匹配的安全规则数据。
          </div>
          <div v-for="rule in rules" :key="rule.id" class="rule_card" @click="fetchRuleXml(rule)">
            <div class="header">
              <span class="id">ID: {{ rule.id }}</span>
              <span class="lvl" :style="{color: getLevelColor(rule.level)}">Level {{ rule.level }}</span>
            </div>
            <div class="body">{{ rule.description }}</div>
            <div class="footer_info">{{ rule.filename }}</div>
          </div>
        </div>
      </div>

      <div v-if="activeTab === 'resources'" class="page_pane">
        <div class="resources_panel">
          <h4 class="resource_title">🛡️ 当前安全线程可视化图谱</h4>
          <p class="resource_desc">系统在溯源分析过程中生成的结构图，请点击按钮查看完整大图。</p>
          
          <div class="svg_button_group">
            <button 
              :disabled="!svgs?.svgChart" 
              :class="['resource_btn', svgs?.svgChart ? 'active' : '']"
              @click="openSvgPreview('分析流转卡片图 (SVG_CHART)', svgs?.svgChart)"
            >
              <span class="icon">📊</span>
              <div class="btn_text">
                <span class="main_t">查看分析流转图</span>
                <span class="sub_t">{{ svgs?.svgChart ? '数据已就绪' : '等待智能体输出...' }}</span>
              </div>
            </button>

            <button 
              :disabled="!svgs?.attackGraph" 
              :class="['resource_btn', svgs?.attackGraph ? 'active' : '']"
              @click="openSvgPreview('溯源攻击拓扑图 (ATTACK_GRAPH)', svgs?.attackGraph)"
            >
              <span class="icon">🕸️</span>
              <div class="btn_text">
                <span class="main_t">查看攻击拓扑图</span>
                <span class="sub_t">{{ svgs?.attackGraph ? '数据已就绪' : '等待智能体输出...' }}</span>
              </div>
            </button>
          </div>

          <div v-if="!svgs?.svgChart && !svgs?.attackGraph" class="no_data_alert">
            💡 提示：当前对话内尚未发现可用的拓扑数据。请在右侧 AI 窗口内让智能体执行攻击溯源任务，图谱将自动在此同步。
          </div>
        </div>
      </div>
    </div>

    <el-dialog 
      v-model="detailVisible" 
      :title="`规则源码: ${currentRule?.filename}`" 
      width="75%"
      destroy-on-close
      append-to-body
    >
      <div class="xml_viewer">
        <div class="xml_header">
          <span>Path: {{ currentRule?.relative_dirname }}/{{ currentRule?.filename }}</span>
        </div>
        <pre class="xml_content">{{ currentRuleXml }}</pre>
      </div>
      <template #footer>
        <button class="close_btn" @click="detailVisible = false">关闭预览</button>
      </template>
    </el-dialog>

    <Teleport to="body">
      <div v-if="isSvgModalOpen" class="global-svg-backdrop" @click.self="isSvgModalOpen = false">
        <div class="global-svg-window">
          <div class="window-header">
            <span>{{ svgModalTitle }}</span>
            <button class="close-x" @click="isSvgModalOpen = false">✕</button>
          </div>
          <div class="window-body" v-html="currentSvgContent"></div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped lang="scss">
.ai_chat_container {
  display: flex;
  flex-direction: column;
  height: 100%;
  max-height: 85vh;
  background: rgba(0, 15, 30, 0.6);
  border: 1px solid rgba(49, 171, 227, 0.3);
  border-radius: 8px;
  padding: 15px;
  overflow: hidden;
  position: relative;

  .top_bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 12px;
    border-bottom: 1px solid rgba(49, 171, 227, 0.2);
    margin-bottom: 15px;

    .agent_tabs {
      display: flex;
      gap: 8px;
      .tab_item {
        padding: 5px 15px;
        font-size: 13px;
        color: #31ABE3;
        border: 1px solid #31ABE3;
        border-radius: 4px;
        cursor: pointer;
        transition: 0.2s;
        &.active { background: #31ABE3; color: #fff; box-shadow: 0 0 10px rgba(49, 171, 227, 0.5); }
        &:hover:not(.active) { background: rgba(49, 171, 227, 0.1); color: #00fdfa; border-color: #00fdfa; }
      }
    }
  }

  .chat_window {
    flex: 1;
    overflow-y: hidden;
    
    .page_pane {
      height: 100%;
      display: flex;
      flex-direction: column;
    }

    .empty_box { 
      text-align: center; 
      color: rgba(255,255,255,0.2); 
      margin-top: 40px; 
      font-size: 13px; 
      strong { color: #00fdfa; font-weight: normal; }
    }
  }
}

// ==========================================
// --- 分析资源专属增加的样式样式 ---
// ==========================================
.resources_panel {
  padding: 10px 5px;
  color: #fff;

  .resource_title { margin: 0 0 8px 0; font-size: 15px; color: #00fdfa; }
  .resource_desc { margin: 0 0 25px 0; font-size: 12px; color: rgba(255,255,255,0.4); }

  .svg_button_group {
    display: flex;
    flex-direction: column;
    gap: 15px;

    .resource_btn {
      display: flex;
      align-items: center;
      gap: 15px;
      padding: 15px 20px;
      border-radius: 6px;
      background: rgba(11, 44, 90, 0.2);
      border: 1px solid rgba(49, 171, 227, 0.2);
      color: rgba(255, 255, 255, 0.3);
      cursor: not-allowed;
      text-align: left;
      transition: all 0.3s ease;

      .icon { font-size: 24px; opacity: 0.4; }
      .btn_text {
        display: flex;
        flex-direction: column;
        .main_t { font-size: 14px; font-weight: bold; margin-bottom: 3px; }
        .sub_t { font-size: 11px; }
      }

      &.active {
        background: rgba(49, 171, 227, 0.1);
        border-color: #31ABE3;
        color: #fff;
        cursor: pointer;
        
        .icon { opacity: 1; }
        .btn_text .main_t { color: #00fdfa; }
        .btn_text .sub_t { color: #31ABE3; }

        &:hover {
          background: rgba(49, 171, 227, 0.2);
          border-color: #00fdfa;
          box-shadow: 0 0 15px rgba(0, 253, 250, 0.2);
          transform: translateY(-1px);
        }
      }
    }
  }

  .no_data_alert {
    margin-top: 30px;
    background: rgba(245, 179, 55, 0.05);
    border: 1px dashed rgba(245, 179, 55, 0.3);
    padding: 12px;
    border-radius: 4px;
    font-size: 12px;
    color: #e3b337;
    line-height: 1.5;
  }
}

// 全局大图弹窗基础样式
.global-svg-backdrop {
  position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
  background: rgba(3, 12, 28, 0.9); backdrop-filter: blur(6px);
  display: flex; justify-content: center; align-items: center; z-index: 99999;
}
.global-svg-window {
  width: 85vw; height: 85vh; background: #061630; border: 1px solid #00c0ff; border-radius: 8px;
  display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 0 30px rgba(0, 192, 255, 0.4);
  .window-header {
    display: flex; justify-content: space-between; align-items: center; padding: 15px 25px;
    background: rgba(0, 192, 255, 0.1); border-bottom: 1px solid rgba(0, 192, 255, 0.2); color: #00fdfa; font-weight: bold; font-size: 16px;
    .close-x { background: none; border: none; color: #00c0ff; font-size: 20px; cursor: pointer; &:hover { color: #fff; } }
  }
  .window-body {
    flex: 1; padding: 25px; overflow: auto; display: flex; justify-content: center; align-items: center; background: #020914;
    :deep(svg) {
      max-width: 100%; max-height: 100%; width: auto; height: auto;
      text { fill: #f0f4fa !important; }
    }
  }
}

// --- 规则查询原有样式区块 ---
.search_group { display: flex; gap: 10px; margin-bottom: 15px; position: relative; }
.input_container { flex: 1; position: relative; }
.input_wrapper {
  display: flex; align-items: center; background: rgba(0, 15, 30, 0.8); border: 1px solid rgba(49, 171, 227, 0.4); border-radius: 4px; padding: 0 10px;
  &.focus { border-color: #00fdfa; box-shadow: 0 0 8px rgba(0, 253, 250, 0.2); }
  .prefix { color: rgba(255,255,255,0.4); font-size: 13px; }
  input { flex: 1; background: transparent; border: none; padding: 10px 12px; color: #fff; outline: none; font-family: monospace; font-size: 13px; }
  .clear { background: none; border: none; color: #666; cursor: pointer; font-size: 18px; &:hover { color: #fff; } }
}

.show_panel_box { position: relative; width: 100%; }
.interactive_panel {
  position: absolute; top: 5px; left: 0; width: 100%; background: #000f1e; border: 1px solid #00fdfa; z-index: 1000;
  max-height: 250px; overflow-y: auto; border-radius: 4px; box-shadow: 0 10px 20px rgba(0,0,0,0.8);
  &::-webkit-scrollbar { width: 4px; }
  &::-webkit-scrollbar-thumb { background: #31ABE3; border-radius: 2px; }
  
  .p_item {
    padding: 10px 15px; display: flex; justify-content: space-between; cursor: pointer; border-bottom: 1px solid rgba(49, 171, 227, 0.1);
    font-size: 13px;
    &:hover { background: rgba(49, 171, 227, 0.15); }
    b { font-family: monospace; }
    span { color: rgba(255, 255, 255, 0.4); font-size: 11px; }
    &.action { background: rgba(0, 253, 250, 0.05); color: #00fdfa; border-bottom: 1px solid #00fdfa; }
  }
}

.rule_list_box {
  flex: 1; overflow-y: auto; padding-right: 4px;
  &::-webkit-scrollbar { width: 4px; }
  &::-webkit-scrollbar-thumb { background: #31ABE3; border-radius: 2px; }
}

.rule_card {
  background: rgba(49, 171, 227, 0.05); border: 1px solid rgba(49, 171, 227, 0.2); padding: 12px 15px; margin-bottom: 10px; border-left: 4px solid #31ABE3; border-radius: 4px; cursor: pointer; transition: 0.2s;
  &:hover { background: rgba(49, 171, 227, 0.12); border-color: #00fdfa; transform: translateX(2px); }
  .header { display: flex; justify-content: space-between; margin-bottom: 6px; .id { color: #00fdfa; font-weight: bold; font-family: monospace; font-size: 13px; } .lvl { font-size: 12px; font-weight: bold; } }
  .body { font-size: 13px; color: #e0e0e0; line-height: 1.4; margin-bottom: 6px; word-break: break-all; }
  .footer_info { font-size: 11px; color: rgba(255,255,255,0.3); text-align: right; font-style: italic; }
}

.refresh_btn { background: #31ABE3; border: none; color: #fff; padding: 0 16px; font-size: 13px; border-radius: 4px; cursor: pointer; font-weight: bold; transition: 0.2s; &:hover { background: #00fdfa; color: #000; } }
.close_btn { background: #333; border: none; color: #fff; padding: 8px 20px; border-radius: 4px; cursor: pointer; font-size: 13px; &:hover { background: #444; } }

.xml_viewer {
  background: #050a0f; border-radius: 4px; overflow: hidden; border: 1px solid rgba(49, 171, 227, 0.3);
  .xml_header { background: rgba(49, 171, 227, 0.1); padding: 8px 15px; font-size: 12px; color: rgba(255,255,255,0.5); border-bottom: 1px solid rgba(49, 171, 227, 0.2); }
  .xml_content {
    margin: 0; padding: 15px; color: #00fdfa; font-family: 'Consolas', 'Monaco', monospace; font-size: 13px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; max-height: 55vh; overflow-y: auto;
    &::-webkit-scrollbar { width: 4px; }
    &::-webkit-scrollbar-thumb { background: #31ABE3; border-radius: 2px; }
  }
}

:deep(.el-dialog) { 
  background: #000f1e !important; border: 1px solid rgba(49, 171, 227, 0.4); box-shadow: 0 0 30px rgba(0, 15, 30, 0.9);
  .el-dialog__title { color: #00fdfa; font-weight: bold; font-size: 15px; }
  .el-dialog__header { border-bottom: 1px solid rgba(49, 171, 227, 0.2); margin-right: 0; padding-bottom: 12px; }
  .el-dialog__body { padding: 20px; }
  .el-dialog__footer { border-top: 1px solid rgba(49, 171, 227, 0.1); padding-top: 12px; }
}
</style>