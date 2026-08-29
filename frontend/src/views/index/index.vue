<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, computed, watch } from 'vue';
import ItemWrap from "@/components/item-wrap";
// 第一页组件
import LeftTop from "./left-top.vue";
import LeftCenter from "./left-center.vue";
import LeftBottom from "./left-bottom.vue";
import CenterMap from "./center-map.vue";
import CenterBottom from "./center-bottom.vue";
import RightTop from "./right-top.vue";
import RightCenter from "./right-center.vue";
import RightBottom from "./right-bottom.vue";

// 第二页组件
import second_right from './second_right.vue';
import alerts_query from './alerts_query.vue';
import archives_query from './archives_query.vue';
import rule_query from './rule_query.vue';
import tactical_summary from './tactical_summary.vue';
import topology_view from './topology_view.vue';
import VulnerabilityQuery from './VulnerabilityQuery.vue';
import vulnerability_overview from './vulnerability_overview.vue';
import asset_list from './asset_list.vue';
import process_monitor from './process_monitor.vue';
import threat_hunt from './threat_hunt.vue';
import SecurityInsights from './security_insights.vue';
import knowledge_graph from './knowledge_graph.vue';
import attack_pattern from './attack_pattern.vue';

// 控制页面切换
const currentPage = ref(1);
const globalSessions = ref<Record<string, any[]>>({});

// 确保此处的 ID 与 second_right 智能体组件内的 id 保持一致
const currentAgentId = ref("router_agent");
const isComponentsReady = ref(false);

// 侧边栏菜单配置（按安全运维工作流分组）
const currentMenu = ref('ai-chat');
const sidebarGroups = [
  {
    title: 'AI 智能助手',
    items: [
      { key: 'ai-chat',    icon: '💬', label: 'AI 对话窗口' },
    ]
  },
  {
    title: '告警与威胁',
    items: [
      { key: 'alerts',     icon: '🚨', label: '告警查询' },
      { key: 'rules',      icon: '📜', label: '规则查询' },
      { key: 'threat-hunt', icon: '🛡️', label: '主动威胁排查' },
    ]
  },
  {
    title: '资产与监控',
    items: [
      { key: 'assets',     icon: '🖥️', label: '受控资产列表' },
      { key: 'process',    icon: '⚙️', label: '进程监控' },
    ]
  },
  {
    title: '日志与漏洞',
    items: [
      { key: 'archives',      icon: '📋', label: '历史日志查询' },
      { key: 'vulnerability', icon: '🔍', label: '漏洞知识实体化' },
      { key: 'vulnerability-overview', icon: '🎯', label: '漏洞信息总览' },
      { key: 'security-insights', icon: '🔭', label: '安全洞察总览' },
      { key: 'attack-pattern', icon: '🧬', label: '攻击特征规律' },
    ]
  },
  {
    title: '可视化分析',
    items: [
      { key: 'tactical',  icon: '📊', label: '战术卡片' },
      { key: 'topology',  icon: '🕸️', label: '攻击拓扑图' },
      { key: 'knowledge-graph', icon: '🧠', label: '知识图谱' },
    ]
  },
];

// 1. 初始化加载
onMounted(() => {
  setTimeout(() => {
    isComponentsReady.value = true;
  }, 100);
  const saved = localStorage.getItem('wazuh_all_sessions');
  if (saved) {
    globalSessions.value = JSON.parse(saved);
  }

  // 监听来自 center-bottom 的跳转请求
  const onNavigateToRules = () => {
    currentPage.value = 2;
    currentMenu.value = 'rules';
  };
  window.addEventListener('navigate-to-rules', onNavigateToRules);
  (window as any).__navigateToRulesHandler = onNavigateToRules;

  // 监听来自 right-bottom（AI 助理监控）的跳转请求
  const onNavigateToAIChat = () => {
    currentPage.value = 2;
    currentMenu.value = 'ai-chat';
  };
  window.addEventListener('navigate-to-ai-chat', onNavigateToAIChat);
  (window as any).__navigateToAIChatHandler = onNavigateToAIChat;

  // 监听来自 right-center（告警查询）的跳转请求
  const onNavigateToAlerts = () => {
    currentPage.value = 2;
    currentMenu.value = 'alerts';
  };
  window.addEventListener('navigate-to-alerts', onNavigateToAlerts);
  (window as any).__navigateToAlertsHandler = onNavigateToAlerts;
});

onBeforeUnmount(() => {
  const handler = (window as any).__navigateToRulesHandler;
  if (handler) {
    window.removeEventListener('navigate-to-rules', handler);
    delete (window as any).__navigateToRulesHandler;
  }
  const chatHandler = (window as any).__navigateToAIChatHandler;
  if (chatHandler) {
    window.removeEventListener('navigate-to-ai-chat', chatHandler);
    delete (window as any).__navigateToAIChatHandler;
  }

  const alertsHandler = (window as any).__navigateToAlertsHandler;
  if (alertsHandler) {
    window.removeEventListener('navigate-to-alerts', alertsHandler);
    delete (window as any).__navigateToAlertsHandler;
  }
});

// 持久化全局会话数据（供 right-bottom 等跨组件读取）
watch(globalSessions, (val) => {
  localStorage.setItem('wazuh_all_sessions', JSON.stringify(val));
}, { deep: true });

// 动态实时从当前的会话流中提取 attack_abstract 数据
const latestAttackAbstract = computed(() => {
  const threadMap = JSON.parse(localStorage.getItem('wazuh_agent_thread_map') || '{}');
  const currentThreadId = threadMap[currentAgentId.value] || "";

  const sessionKey = `${currentAgentId.value}_${currentThreadId}`;
  const currentChatList = globalSessions.value[sessionKey] || [];

  for (let i = currentChatList.length - 1; i >= 0; i--) {
    const msg = currentChatList[i];
    if (msg.role === 'assistant' && msg.node === 'tools' && msg.content) {
      try {
        const toolData = typeof msg.content === 'string' ? JSON.parse(msg.content) : msg.content;

        if (toolData?.artifacts?.attack_abstract) {
          return toolData.artifacts.attack_abstract;
        }
      } catch (e) {
        console.warn("第二页主组件解析 artifacts 失败:", e);
      }
    }
  }
  return null;
});

// 动态实时提取 svg_chart 和 attack_graph 数据
const latestAttackSvgs = computed(() => {
  const threadMap = JSON.parse(localStorage.getItem('wazuh_agent_thread_map') || '{}');
  const currentThreadId = threadMap[currentAgentId.value] || "";

  const sessionKey = `${currentAgentId.value}_${currentThreadId}`;
  const currentChatList = globalSessions.value[sessionKey] || [];

  for (let i = currentChatList.length - 1; i >= 0; i--) {
    const msg = currentChatList[i];
    if (msg.role === 'assistant' && msg.node === 'tools' && msg.content) {
      try {
        const toolData = typeof msg.content === 'string' ? JSON.parse(msg.content) : msg.content;

        if (toolData?.artifacts) {
          return {
            svgChart: toolData.artifacts.svg_chart || null,
            attackGraph: toolData.artifacts.attack_graph || null
          };
        }
      } catch (e) {
        continue;
      }
    }
  }
  return { svgChart: null, attackGraph: null };
});
</script>

<template>
  <div class="main-container">
    <div class="page-controls">
      <button @click="currentPage = 1" :class="{ active: currentPage === 1 }">数智运营大屏</button>
      <button @click="currentPage = 2" :class="{ active: currentPage === 2 }">数智运维工作台</button>
    </div>

    <div v-if="currentPage === 1 && isComponentsReady" class="index-box">
      <div class="contetn_left">
        <ItemWrap class="contetn_left-top contetn_lr-item" title="资产监控概览"><LeftTop /></ItemWrap>
        <ItemWrap class="contetn_left-center contetn_lr-item" title="告警等级分布"><LeftCenter /></ItemWrap>
        <ItemWrap class="contetn_left-bottom contetn_lr-item" title="实时告警事件" style="padding: 0 10px 16px 10px"><LeftBottom /></ItemWrap>
      </div>
      <div class="contetn_center">
        <CenterMap class="contetn_center_top" title="网络拓扑监控" />
        <ItemWrap class="contetn_center-bottom" title="规则风险分析"><CenterBottom /></ItemWrap>
      </div>
      <div class="contetn_right">
        <ItemWrap class="contetn_left-bottom contetn_lr-item" title="告警趋势分析"><RightTop /></ItemWrap>
        <ItemWrap class="contetn_left-bottom contetn_lr-item" title="高频告警排行" style="padding: 0 10px 16px 10px"><RightCenter /></ItemWrap>
        <ItemWrap class="contetn_left-bottom contetn_lr-item" title="AI 会话监控"><RightBottom :sessions="globalSessions" :agent-id="currentAgentId" /></ItemWrap>
      </div>
    </div>

    <div v-else class="second-page-box">
      <!-- 侧边栏导航 -->
      <div class="sidebar-wrapper">
        <div class="sidebar-header">
          <span class="sidebar-title-icon">🛰</span>
          <span class="sidebar-title-text">功能导航</span>
        </div>
        <div class="sidebar-nav">
          <template v-for="group in sidebarGroups" :key="group.title">
            <div class="nav-group-title">{{ group.title }}</div>
            <div
              v-for="item in group.items"
              :key="item.key"
              :class="['nav-item', currentMenu === item.key ? 'nav-item--active' : '']"
              @click="currentMenu = item.key"
            >
              <span class="nav-icon">{{ item.icon }}</span>
              <span class="nav-label">{{ item.label }}</span>
            </div>
          </template>
        </div>
      </div>

      <!-- 右侧内容区 -->
      <div class="main-content">
        <template v-if="currentMenu === 'ai-chat'">
          <second_right v-model:sessions="globalSessions" v-model:agent-id="currentAgentId" />
        </template>
        <template v-else-if="currentMenu === 'alerts'">
          <alerts_query :attack-abstract="latestAttackAbstract" />
        </template>
        <template v-else-if="currentMenu === 'archives'">
          <archives_query />
        </template>
        <template v-else-if="currentMenu === 'rules'">
          <rule_query />
        </template>
        <template v-else-if="currentMenu === 'tactical'">
          <tactical_summary :attack-abstract="latestAttackAbstract" />
        </template>
        <template v-else-if="currentMenu === 'vulnerability'">
          <VulnerabilityQuery />
        </template>
        <template v-else-if="currentMenu === 'vulnerability-overview'">
          <vulnerability_overview />
        </template>
        <template v-else-if="currentMenu === 'security-insights'">
          <SecurityInsights />
        </template>
        <template v-else-if="currentMenu === 'attack-pattern'">
          <attack_pattern />
        </template>
        <template v-else-if="currentMenu === 'assets'">
          <asset_list />
        </template>
        <template v-else-if="currentMenu === 'process'">
          <process_monitor />
        </template>
        <template v-else-if="currentMenu === 'threat-hunt'">
          <threat_hunt />
        </template>
        <template v-else-if="currentMenu === 'topology'">
          <topology_view :svgs="latestAttackSvgs" />
        </template>
        <template v-else-if="currentMenu === 'knowledge-graph'">
          <knowledge_graph />
        </template>
      </div>
    </div>
  </div>
</template>

<style scoped lang="scss">
.main-container {
  width: 100%;
  height: 100%;
}
.index-box {
  width: 100%;
  display: flex;
  min-height: calc(100% - 64px);
  justify-content: space-between;
}
.contetn_left, .contetn_right {
  display: flex;
  flex-direction: column;
  justify-content: space-around;
  position: relative;
  width: 540px;
  box-sizing: border-box;
  flex-shrink: 0;
}
.contetn_center {
  flex: 1;
  margin: 0 54px;
  display: flex;
  flex-direction: column;
  justify-content: space-around;
  .contetn_center-bottom { height: 315px; }
}
.contetn_lr-item { height: 310px; }

// ── 第二页：侧边栏布局 ──
.second-page-box {
  flex: 1;
  margin: 0 54px;
  display: flex;
  flex-direction: row;
  gap: 20px;
  height: calc(100% - 64px);
  min-height: 0;
  overflow: hidden;
}

// ── 侧边栏 ──
.sidebar-wrapper {
  width: 200px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  background: #ffffff;
  border: 1px solid var(--border, #e5e7eb);
  border-radius: 10px;
  overflow: hidden;
  height: 100%;
}

.sidebar-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--border, #e5e7eb);
  background: #f8fafc;
  flex-shrink: 0;

  .sidebar-title-icon {
    font-size: 16px;
  }

  .sidebar-title-text {
    font-size: 13px;
    font-weight: 700;
    color: #1d4ed8;
    letter-spacing: 1px;
  }
}

.sidebar-nav {
  flex: 1;
  overflow-y: auto;
  padding: 8px 10px;
  display: flex;
  flex-direction: column;
  gap: 2px;

  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb {
    background: color-mix(in oklab, var(--muted-foreground, #7c8a9e) 15%, transparent);
    border-radius: 2px;
  }
}

.nav-group-title {
  font-size: 11px;
  font-weight: 700;
  color: #9ca3af;
  letter-spacing: 0.5px;
  padding: 10px 14px 4px;
  text-transform: uppercase;
  user-select: none;

  &:first-of-type {
    padding-top: 4px;
  }
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
  border: 1px solid transparent;
  user-select: none;

  .nav-icon {
    font-size: 16px;
    line-height: 1;
    flex-shrink: 0;
  }

  .nav-label {
    font-size: 13px;
    font-weight: 500;
    color: var(--muted-foreground, #7c8a9e);
    transition: color 0.2s ease;
    white-space: nowrap;
  }

  &:hover {
    background: rgba(49, 171, 227, 0.06);
    border-color: rgba(49, 171, 227, 0.1);
    .nav-label { color: var(--foreground, #1f2937); }
  }

  &--active {
    background: rgba(49, 171, 227, 0.1);
    border-color: rgba(49, 171, 227, 0.2);
    box-shadow: inset 3px 0 0 #31ABE3;

    .nav-label {
      color: #1d4ed8;
      font-weight: 600;
    }

    .nav-icon {
      filter: drop-shadow(0 0 4px rgba(49, 171, 227, 0.4));
    }

    &:hover {
      background: rgba(49, 171, 227, 0.12);
      .nav-label { color: #1d4ed8; }
    }
  }
}

// ── 右侧内容区 ──
.main-content {
  flex: 1;
  min-width: 0;
  height: 100%;
  overflow: hidden;
  border-radius: 10px;
  background: transparent;

  :deep(> *) {
    height: 100%;
  }
}

.page-controls {
  position: absolute;
  top: 44px;
  left: 10%;
  transform: translateX(-50%);
  z-index: 99;
  button {
    margin: 0 10px;
    padding: 5px 15px;
    background: #e0f2fe;
    border: 1px solid #93c5fd;
    color: #1e40af;
    cursor: pointer;
    &.active { background: #3b82f6; }
  }
}
</style>
