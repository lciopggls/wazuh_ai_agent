<script setup lang="ts">
import { ref, onMounted, nextTick, computed } from "vue";

// --- 1. 配置与状态定义 ---
const agents = [
  { id: 'demo_agent', name: '测试智能体' },
  { id: 'attack_attribution', name: '攻击溯源' }
];

// 当前选中的智能体 ID
const currentAgentId = ref("demo_agent");

// 核心：智能体与线程 ID 的映射表，确保记忆隔离
// 结构：{ "demo_agent": "tid_xxx", "attack_attribution": "tid_yyy" }
const agentThreadMap = ref<Record<string, string>>({});

// 核心：存储所有对话记录
// 结构：{ "agentId_threadId": [messages] }
const allSessions = ref<Record<string, any[]>>({});

const userInput = ref("");
const isTyping = ref(false);
const scrollRef = ref<HTMLElement | null>(null);

// --- 2. 计算属性 ---

// 获取当前活跃的线程 ID
const currentThreadId = computed(() => {
  return agentThreadMap.value[currentAgentId.value] || "";
});

// 获取当前应该显示的聊天列表
const chatList = computed(() => {
  const key = `${currentAgentId.value}_${currentThreadId.value}`;
  return allSessions.value[key] || [];
});

// --- 3. 生命周期与持久化 ---

onMounted(() => {
  // 从本地存储恢复数据
  const savedMap = localStorage.getItem('wazuh_agent_thread_map');
  const savedSessions = localStorage.getItem('wazuh_all_sessions');
  
  if (savedMap) agentThreadMap.value = JSON.parse(savedMap);
  if (savedSessions) allSessions.value = JSON.parse(savedSessions);

  // 初始化检查：确保每个智能体都有一个初始线程
  agents.forEach(agent => {
    if (!agentThreadMap.value[agent.id]) {
      const initialId = `tid_${Math.random().toString(36).substr(2, 9)}`;
      agentThreadMap.value[agent.id] = initialId;
      
      const sessionKey = `${agent.id}_${initialId}`;
      if (!allSessions.value[sessionKey]) {
        allSessions.value[sessionKey] = [];
      }
    }
  });
});

const saveToLocal = () => {
  localStorage.setItem('wazuh_agent_thread_map', JSON.stringify(agentThreadMap.value));
  localStorage.setItem('wazuh_all_sessions', JSON.stringify(allSessions.value));
};

// 创建新线程逻辑
const createNewThread = () => {
  const newId = `tid_${Math.random().toString(36).substr(2, 9)}`;
  
  // 只更新当前智能体的线程，实现清空效果
  agentThreadMap.value[currentAgentId.value] = newId;
  
  const newKey = `${currentAgentId.value}_${newId}`;
  allSessions.value[newKey] = [];
  
  saveToLocal();
};

// --- 4. 核心发送逻辑 ---

const handleSend = async () => {
  if (!userInput.value.trim() || isTyping.value) return;

  const msg = userInput.value;
  const agentId = currentAgentId.value;
  const threadId = currentThreadId.value;
  const sessionKey = `${agentId}_${threadId}`;

  // 1. 存入用户消息
  allSessions.value[sessionKey].push({ role: 'user', content: msg });
  userInput.value = "";
  isTyping.value = true;

  // 2. 存入 AI 占位符
  const aiMsgIndex = allSessions.value[sessionKey].push({ 
    role: 'assistant', content: "", node: "" 
  }) - 1;

  await nextTick();
  scrollToBottom();

  try {
    const response = await fetch('http://127.0.0.1:8001/api/chat/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: msg,
        thread_id: threadId,
        agent_id: agentId
      })
    });

    if (!response.body) throw new Error("ReadableStream not supported");

    const reader = response.body.getReader();
    const decoder = new TextDecoder();

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      const chunk = decoder.decode(value);
      const lines = chunk.split('\n');

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const dataStr = line.replace('data: ', '').trim();
          
          if (dataStr === '[DONE]') {
            isTyping.value = false;
            saveToLocal();
            break;
          }

          try {
            const data = JSON.parse(dataStr);
            if (data.content) {
              // 关键：更新对应 Session 中的消息
              allSessions.value[sessionKey][aiMsgIndex].content += `\n**[${data.node}]**: ${data.content}\n`;
              allSessions.value[sessionKey][aiMsgIndex].node = data.node;
              
              await nextTick();
              scrollToBottom();
            }
          } catch (e) {}
        }
      }
    }
  } catch (error: any) {
    allSessions.value[sessionKey][aiMsgIndex].content = `❌ 错误: ${error.message}`;
  } finally {
    isTyping.value = false;
    await nextTick();
    scrollToBottom();
  }
};

const scrollToBottom = () => {
  if (scrollRef.value) {
    scrollRef.value.scrollTop = scrollRef.value.scrollHeight;
  }
};
</script>

<template>
  <div class="ai_chat_container">
    <!-- 顶部导航栏 -->
    <div class="top_bar">
      <div class="agent_tabs">
        <div 
          v-for="agent in agents" 
          :key="agent.id"
          :class="['tab_item', currentAgentId === agent.id ? 'active' : '']"
          @click="currentAgentId = agent.id"
        >
          {{ agent.name }}
        </div>
      </div>
      
      <div class="thread_controls">
        <span class="thread_id_tag">SID: {{ currentThreadId }}</span>
        <button @click="createNewThread" class="new_btn">+ 新对话</button>
      </div>
    </div>

    <!-- 聊天视窗 -->
    <div class="chat_window" ref="scrollRef">
      <div v-if="chatList.length === 0" class="empty_box">
        已切换至 <strong>{{ currentAgentId }}</strong>，当前会话暂无数据。
      </div>
      
      <div
        v-for="(msg, index) in chatList"
        :key="index"
        :class="['msg_row', msg.role === 'user' ? 'row_user' : 'row_ai']"
      >
        <div class="avatar">{{ msg.role === 'user' ? 'ME' : 'AI' }}</div>
        <div class="content_box">
          <div v-if="msg.role === 'assistant' && msg.node" class="node_tag">
            执行节点: {{ msg.node }}
          </div>
          <p class="text">{{ msg.content || (isTyping && index === chatList.length -1 ? '正在处理...' : '') }}</p>
        </div>
      </div>
      <div v-if="isTyping" class="typing_indicator">智能体正在响应请求...</div>
    </div>

    <!-- 输入区 -->
    <div class="input_area">
      <input
        v-model="userInput"
        type="text"
        placeholder="发送指令给当前智能体..."
        @keyup.enter="handleSend"
      />
      <button @click="handleSend" :disabled="isTyping">发送</button>
    </div>
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
      }
    }

    .thread_controls {
      display: flex;
      align-items: center;
      gap: 12px;
      .thread_id_tag { font-size: 11px; color: rgba(255,255,255,0.4); font-family: monospace; }
      .new_btn {
        background: transparent;
        border: 1px dashed #00fdfa;
        color: #00fdfa;
        padding: 3px 10px;
        font-size: 12px;
        cursor: pointer;
        border-radius: 4px;
        &:hover { background: rgba(0, 253, 250, 0.1); }
      }
    }
  }

  .chat_window {
    flex: 1;
    overflow-y: auto;
    padding-right: 8px;
    margin-bottom: 15px;

    .empty_box { text-align: center; color: rgba(255,255,255,0.2); margin-top: 40px; font-size: 13px; }

    &::-webkit-scrollbar { width: 4px; }
    &::-webkit-scrollbar-thumb { background: #31ABE3; border-radius: 2px; }

    .msg_row {
      display: flex;
      margin-bottom: 20px;
      animation: fadeIn 0.3s ease;

      .avatar { width: 32px; height: 32px; border-radius: 50%; font-size: 10px; line-height: 32px; text-align: center; flex-shrink: 0; }
      .content_box {
        max-width: 80%;
        padding: 10px 14px;
        border-radius: 8px;
        font-size: 13.5px;
        .node_tag { font-size: 10px; color: #31ABE3; margin-bottom: 6px; font-weight: bold; }
        .text { white-space: pre-wrap; margin: 0; }
      }
    }

    .row_ai {
      .avatar { background: #31ABE3; color: #fff; margin-right: 12px; }
      .content_box { background: rgba(49, 171, 227, 0.08); border: 1px solid rgba(49, 171, 227, 0.2); color: #e0e0e0; }
    }

    .row_user {
      flex-direction: row-reverse;
      .avatar { background: #00fdfa; color: #000; margin-left: 12px; }
      .content_box { background: rgba(0, 253, 250, 0.08); border: 1px solid rgba(0, 253, 250, 0.2); color: #fff; }
    }
  }

  .typing_indicator { font-size: 12px; color: #31ABE3; margin-bottom: 10px; font-style: italic; opacity: 0.8; }

  .input_area {
    display: flex;
    gap: 10px;
    height: 45px;
    input {
      flex: 1;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(49, 171, 227, 0.4);
      border-radius: 6px;
      color: #fff;
      padding: 0 15px;
      outline: none;
      &:focus { border-color: #00fdfa; box-shadow: 0 0 5px rgba(0, 253, 250, 0.2); }
    }
    button {
      width: 70px;
      background: #31ABE3;
      border: none;
      border-radius: 6px;
      color: #fff;
      font-weight: bold;
      cursor: pointer;
      transition: 0.3s;
      &:disabled { opacity: 0.4; cursor: not-allowed; }
      &:hover:not(:disabled) { background: #00fdfa; color: #000; }
    }
  }
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>