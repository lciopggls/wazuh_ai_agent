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

// 控制页面切换
const currentPage = ref(1);
const globalSessions = ref<Record<string, any[]>>({});

// 确保此处的 ID 与 second_right 智能体组件内的 id 保持一致
const currentAgentId = ref("router_agent");
const isComponentsReady = ref(false);

// 侧边栏菜单配置
const currentMenu = ref('ai-chat');
const sidebarMenu = [
  { key: 'ai-chat',    icon: '💬', label: 'AI 对话窗口' },
  { key: 'alerts',     icon: '🚨', label: '告警查询' },
  { key: 'archives',   icon: '📋', label: '历史日志查询' },
  { key: 'rules',      icon: '📜', label: '规则查询' },
  { key: 'tactical',   icon: '📊', label: '战术卡片' },
  { key: 'topology',   icon: '🕸️', label: '攻击拓扑图' },
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
      <button @click="currentPage = 1" :class="{ active: currentPage === 1 }">第一页</button>
      <button @click="currentPage = 2" :class="{ active: currentPage === 2 }">第二页</button>
    </div>

    <div v-if="currentPage === 1 && isComponentsReady" class="index-box">
      <div class="contetn_left">
        <ItemWrap class="contetn_left-top contetn_lr-item" title="设备总览"><LeftTop /></ItemWrap>
        <ItemWrap class="contetn_left-center contetn_lr-item" title="警告总览"><LeftCenter /></ItemWrap>
        <ItemWrap class="contetn_left-bottom contetn_lr-item" title="设备提醒" style="padding: 0 10px 16px 10px"><LeftBottom /></ItemWrap>
      </div>
      <div class="contetn_center">
        <CenterMap class="contetn_center_top" title="设备分布图" />
        <ItemWrap class="contetn_center-bottom" title="规则概览"><CenterBottom /></ItemWrap>
      </div>
      <div class="contetn_right">
        <ItemWrap class="contetn_left-bottom contetn_lr-item" title="报警次数"><RightTop /></ItemWrap>
        <ItemWrap class="contetn_left-bottom contetn_lr-item" title="报警查询" style="padding: 0 10px 16px 10px"><RightCenter /></ItemWrap>
        <ItemWrap class="contetn_left-bottom contetn_lr-item" title="AI 助理监控"><RightBottom :sessions="globalSessions" :agent-id="currentAgentId" /></ItemWrap>
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
          <div
            v-for="item in sidebarMenu"
            :key="item.key"
            :class="['nav-item', currentMenu === item.key ? 'nav-item--active' : '']"
            @click="currentMenu = item.key"
          >
            <span class="nav-icon">{{ item.icon }}</span>
            <span class="nav-label">{{ item.label }}</span>
          </div>
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
        <template v-else-if="currentMenu === 'topology'">
          <topology_view :svgs="latestAttackSvgs" />
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
  background: rgba(10, 14, 23, 0.8);
  border: 1px solid var(--border, rgba(49, 171, 227, 0.12));
  border-radius: 10px;
  overflow: hidden;
  height: 100%;
}

.sidebar-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--border, rgba(49, 171, 227, 0.12));
  background: color-mix(in oklab, #0a0e17 97%, #31ABE3);
  flex-shrink: 0;

  .sidebar-title-icon {
    font-size: 16px;
  }

  .sidebar-title-text {
    font-size: 13px;
    font-weight: 700;
    color: #00fdfa;
    letter-spacing: 1px;
  }
}

.sidebar-nav {
  flex: 1;
  overflow-y: auto;
  padding: 8px 10px;
  display: flex;
  flex-direction: column;
  gap: 4px;

  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb {
    background: color-mix(in oklab, var(--muted-foreground, #7c8a9e) 15%, transparent);
    border-radius: 2px;
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
    .nav-label { color: var(--foreground, #d3d6dd); }
  }

  &--active {
    background: rgba(49, 171, 227, 0.1);
    border-color: rgba(49, 171, 227, 0.2);
    box-shadow: inset 3px 0 0 #31ABE3;

    .nav-label {
      color: #31ABE3;
      font-weight: 600;
    }

    .nav-icon {
      filter: drop-shadow(0 0 4px rgba(49, 171, 227, 0.4));
    }

    &:hover {
      background: rgba(49, 171, 227, 0.12);
      .nav-label { color: #00fdfa; }
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
    background: #0b2c5a;
    border: 1px solid #00c0ff;
    color: #fff;
    cursor: pointer;
    &.active { background: #00c0ff; }
  }
}
</style>
