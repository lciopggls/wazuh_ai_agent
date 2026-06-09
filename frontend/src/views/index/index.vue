<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
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
import second_left from './second_left.vue';     // 👈 期望放入战术卡片/摘要的地方
import second_middle from './second_middle.vue';
import second_right from './second_right.vue';   // 👈 AI 聊天窗口组件

// 控制页面切换
const currentPage = ref(1);
const globalSessions = ref<Record<string, any[]>>({});

// 💡 确保此处的 ID 与你的 second_right 智能体组件内的 id: 'attack_attributor' 保持完全一致
const currentAgentId = ref("attack_attributor"); 

// 1. 初始化加载
onMounted(() => {
  const saved = localStorage.getItem('wazuh_all_sessions');
  if (saved) {
    globalSessions.value = JSON.parse(saved);
  }
});

// 2. 统一保存方法
const updateAndSaveSessions = (newSessions: Record<string, any[]>) => {
  globalSessions.value = { ...newSessions };
  localStorage.setItem('wazuh_all_sessions', JSON.stringify(globalSessions.value));
};

// 3. 清空处理逻辑
const handleGlobalClear = (agentId: string) => {
  const updated = { ...globalSessions.value };
  Object.keys(updated).forEach(key => {
    if (key.startsWith(agentId)) {
      updated[key] = []; // 彻底清空该智能体下的所有会话消息
    }
  });
  updateAndSaveSessions(updated);
};

// ⚡ 核心：动态实时从当前的会话流中提取 attack_abstract 数据，供第二页的左侧组件使用
const latestAttackAbstract = computed(() => {
  // 从本地持久化中动态获取当前智能体激活的 thread_id
  const threadMap = JSON.parse(localStorage.getItem('wazuh_agent_thread_map') || '{}');
  const currentThreadId = threadMap[currentAgentId.value] || "";
  
  const sessionKey = `${currentAgentId.value}_${currentThreadId}`;
  const currentChatList = globalSessions.value[sessionKey] || [];

  // 从后往前寻找最新生成的 tools 数据节点
  for (let i = currentChatList.length - 1; i >= 0; i--) {
    const msg = currentChatList[i];
    if (msg.role === 'assistant' && msg.node === 'tools' && msg.content) {
      try {
        const toolData = typeof msg.content === 'string' ? JSON.parse(msg.content) : msg.content;
        
        if (toolData?.artifacts?.attack_abstract) {
          return toolData.artifacts.attack_abstract; // 成功提取到战术摘要对象
        }
      } catch (e) {
        console.warn("第二页主组件解析 artifacts 失败:", e);
      }
    }
  }
  return null;
});
// ⚡ 核心：动态实时从当前的会话流中提取 svg_chart 和 attack_graph 数据
const latestAttackSvgs = computed(() => {
  const threadMap = JSON.parse(localStorage.getItem('wazuh_agent_thread_map') || '{}');
  const currentThreadId = threadMap[currentAgentId.value] || "";
  
  const sessionKey = `${currentAgentId.value}_${currentThreadId}`;
  const currentChatList = globalSessions.value[sessionKey] || [];

  // 从后往前寻找最新生成的 tools 数据节点
  for (let i = currentChatList.length - 1; i >= 0; i--) {
    const msg = currentChatList[i];
    if (msg.role === 'assistant' && msg.node === 'tools' && msg.content) {
      try {
        const toolData = typeof msg.content === 'string' ? JSON.parse(msg.content) : msg.content;
        
        // 只要 artifacts 存在，哪怕流式传输时只出来了其中一个图，也能兼容拿到
        if (toolData?.artifacts) {
          return {
            svgChart: toolData.artifacts.svg_chart || null,
            attackGraph: toolData.artifacts.attack_graph || null
          };
        }
      } catch (e) {
        // 流式解析未闭合时允许报错跳过
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

    <div v-if="currentPage === 1" class="index-box">
      <div class="contetn_left">
        <ItemWrap class="contetn_left-top contetn_lr-item" title="设备总览"><LeftTop /></ItemWrap>
        <ItemWrap class="contetn_left-center contetn_lr-item" title="警告总览"><LeftCenter /></ItemWrap>
        <ItemWrap class="contetn_left-bottom contetn_lr-item" title="设备提醒" style="padding: 0 10px 16px 10px"><LeftBottom /></ItemWrap>
      </div>
      <div class="contetn_center">
        <CenterMap class="contetn_center_top" title="设备分布图" />
        <ItemWrap class="contetn_center-bottom" title="规则查询"><CenterBottom /></ItemWrap>
      </div>
      <div class="contetn_right">
        <ItemWrap class="contetn_left-bottom contetn_lr-item" title="报警次数"><RightTop /></ItemWrap>
        <ItemWrap class="contetn_left-bottom contetn_lr-item" title="报警查询" style="padding: 0 10px 16px 10px"><RightCenter /></ItemWrap>
        <ItemWrap class="contetn_left-bottom contetn_lr-item" title="ai聊天窗口"><RightBottom /></ItemWrap>
      </div>
    </div>

    <div v-else class="second-page-box">
      <div class="column-wrapper">
        
        <ItemWrap class="fixed-column" title="业务模块一">
          <second_left :attack-abstract="latestAttackAbstract" />
        </ItemWrap>
        
        <ItemWrap class="fixed-column" title="业务模块二">
          <second_middle 
          :all-sessions="globalSessions" 
          :agent-id="currentAgentId" 
          @clear-sessions="handleGlobalClear"
          :svgs="latestAttackSvgs" />
        </ItemWrap>
        
        <ItemWrap class="fixed-column" title="业务模块三">
          <second_right 
          v-model:sessions="globalSessions" 
          v-model:agent-id="currentAgentId" />
        </ItemWrap>
      </div>
    </div>
  </div>
</template>

<style scoped lang="scss">
/* 你的原始样式保持绝对不变 */
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

.second-page-box {
  flex: 1;
  margin: 0 54px;
  display: flex;
  flex-direction: column;
  justify-content: space-around;
  
  .column-wrapper {
    display: flex;
    gap: 40px;
  }

  .fixed-column {
    width: 540px; 
    height: 960px; 
    flex-shrink: 0;
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