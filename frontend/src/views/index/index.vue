<script setup lang="ts">
import { ref, onMounted } from 'vue';
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
import second_left from './second_left.vue';
import second_middle from './second_middle.vue';
import second_right from './second_right.vue';
// 控制页面切换
const currentPage = ref(1);
const globalSessions = ref<Record<string, any[]>>({});

// 2. 定义当前选中的智能体和会话ID（应与智能体组件内的逻辑对应）
const currentAgentId = ref("attack_attribution"); 
const currentThreadId = ref(""); // 可以在初始化时或由左侧组件传回

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
</script>

<template>
  <div class="main-container">
    <!-- 切换按钮（示例用，可根据业务逻辑触发） -->
    <div class="page-controls">
      <button @click="currentPage = 1" :class="{ active: currentPage === 1 }">第一页</button>
      <button @click="currentPage = 2" :class="{ active: currentPage === 2 }">第二页</button>
    </div>

    <!-- 第一页布局：保持原有逻辑完全不动 -->
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

    <!-- 第二页布局：新增三个固定大小的长方形 -->
    <div v-else class="second-page-box">
      <div class="column-wrapper">
        <ItemWrap class="fixed-column" title="业务模块一">
          <!-- 这里放入你的新组件 -->
          <second_left />
        </ItemWrap>
        
        <ItemWrap class="fixed-column" title="业务模块二">
          <second_middle :all-sessions="globalSessions" :agent-id="currentAgentId" @clear-sessions="handleGlobalClear" />
        </ItemWrap>
        
        <ItemWrap class="fixed-column" title="业务模块三">
          <second_right v-model:sessions="globalSessions" :agent-id="currentAgentId" />
        </ItemWrap>
      </div>
    </div>
  </div>
</template>

<style scoped lang="scss">
// 共有容器
.main-container {
  width: 100%;
  height: 100%;
}

// 第一页样式（保留你原始的所有样式）
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

// 第二页样式：新增
.second-page-box {
  flex: 1;
  margin: 0 54px;
  display: flex;
  flex-direction: column;
  justify-content: space-around;
  
  .column-wrapper {
    display: flex;
    gap: 40px; // 三个长方形之间的间距
  }

  .fixed-column {
    // 设定固定宽高，防止由于拉伸导致的“巨大感”
    width: 540px; 
    height: 960px; 
    flex-shrink: 0;
  }
}

// 辅助样式
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
.content-placeholder {
  color: #fff;
  text-align: center;
  padding-top: 100px;
}
</style>