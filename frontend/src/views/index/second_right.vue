<script setup lang="ts">
import { ref, onMounted, nextTick, computed, watch } from "vue";
import VueMarkdown from 'vue-markdown-render';

// --- 1. 配置与状态定义 ---
// ⚡ 修改点：将 agentId 提升为从父组件传入，便于全局共享当前选中状态
const props = defineProps<{
  sessions: Record<string, any[]>;
  agentId: string; 
}>();

const emit = defineEmits(['update:sessions', 'update:agentId']);

// 智能体配置列表（当前仅保留路由智能体）
const agents = [
  { id: 'router_agent', name: '路由智能体' }
];

// 当前活跃智能体（基于 prop 的计算属性，切换时通知父组件）
const currentAgentId = computed({
  get: () => props.agentId || "router_agent",
  set: (val: string) => emit('update:agentId', val)
});

// 智能体与线程 ID 的映射表（本地持久化）
const agentThreadMap = ref<Record<string, string>>(
  JSON.parse(localStorage.getItem('wazuh_agent_thread_map') || '{}')
);

const userInput = ref("");
const isTyping = ref(false);
const scrollRef = ref<HTMLElement | null>(null);

// --- 2. 计算属性 ---

// 获取当前智能体的所有历史线程 ID
const historyThreads = computed(() => {
  const prefix = `${currentAgentId.value}_`;
  return Object.keys(props.sessions)
    .filter(key => key.startsWith(prefix))
    .map(key => key.replace(prefix, ''));
});

// 获取或设置当前活跃的线程 ID
const currentThreadId = computed({
  get: () => agentThreadMap.value[currentAgentId.value] || "",
  set: (newTid: string) => {
    agentThreadMap.value[currentAgentId.value] = newTid;
    localStorage.setItem('wazuh_agent_thread_map', JSON.stringify(agentThreadMap.value));
  }
});

// 获取当前应该显示的聊天列表
const chatList = computed(() => {
  const key = `${currentAgentId.value}_${currentThreadId.value}`;
  return props.sessions[key] || [];
});

// --- 3. 初始化与切换逻辑 ---

const initAgentThread = (agentId: string) => {
  if (!agentThreadMap.value[agentId]) {
    const initialId = `tid_${Math.random().toString(36).substring(2, 11)}`;
    agentThreadMap.value[agentId] = initialId;
    return true;
  }
  return false;
};

onMounted(() => {
  let mapChanged = false;
  agents.forEach(agent => {
    if (initAgentThread(agent.id)) mapChanged = true;
  });

  if (mapChanged) {
    localStorage.setItem('wazuh_agent_thread_map', JSON.stringify(agentThreadMap.value));
  }
});

// 监听智能体切换，确保线程安全跟随
watch(currentAgentId, (newAgentId) => {
  if (!agentThreadMap.value[newAgentId]) {
    initAgentThread(newAgentId);
    localStorage.setItem('wazuh_agent_thread_map', JSON.stringify(agentThreadMap.value));
  }
});

// 创建新对话
const createNewThread = () => {
  const newId = `tid_${Math.random().toString(36).substring(2, 11)}`;
  currentThreadId.value = newId;

  const newKey = `${currentAgentId.value}_${newId}`;
  
  const updatedSessions = { ...props.sessions };
  updatedSessions[newKey] = [];
  
  emit('update:sessions', updatedSessions);
};

// 💡 动态拼装 Markdown 代码块辅助函数
const formatMarkdownSource = (msg: any) => {
  if (!msg || !msg.content) return "";
  if (msg.node === 'tools') {
    const ticks = String.fromCharCode(96) + String.fromCharCode(96) + String.fromCharCode(96);
    return `${ticks}json\n${msg.content}\n${ticks}`;
  }
  return msg.content;
};

// --- 4. 核心发送与流式渲染逻辑 ---

const handleSend = async () => {
  if (!userInput.value.trim() || isTyping.value) return;

  const msg = userInput.value;
  const aid = currentAgentId.value;
  const tid = currentThreadId.value;
  const sessionKey = `${aid}_${tid}`;

  // 初始化用户发送的消息
  const initSessions = { ...props.sessions };
  const currentSessionList = initSessions[sessionKey] ? [...initSessions[sessionKey]] : [];
  currentSessionList.push({ role: 'user', content: msg });
  initSessions[sessionKey] = currentSessionList;
  
  userInput.value = "";
  isTyping.value = true;
  emit('update:sessions', initSessions);

  let lastNodeName = "";
  let currentAiMsgIndex = -1; 

  await nextTick();
  scrollToBottom();

  try {
    const response = await fetch('http://127.0.0.1:8001/api/chat/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg, thread_id: tid, agent_id: aid })
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
        if (!line.startsWith('data: ')) continue;
        
        const dataStr = line.replace('data: ', '').trim();
        if (dataStr === '[DONE]') break;

        let incomingContent = "";
        let nodeName = lastNodeName || "model"; 
        let isJsonNode = false;
        let extractedReply = "";

        try {
          const data = JSON.parse(dataStr);
          nodeName = data.node || lastNodeName || "model";
          
          if (nodeName === 'tools') {
            isJsonNode = true;
            
            let parsedInnerContent: any = null;
            if (data.content) {
              try {
                parsedInnerContent = typeof data.content === 'string' ? JSON.parse(data.content) : data.content;
              } catch (innerErr) {
                console.warn("二次反序列化 tools.content 失败:", innerErr);
              }
            }

            if (parsedInnerContent) {
              incomingContent = JSON.stringify(parsedInnerContent, null, 2);
              if (parsedInnerContent.reply) {
                extractedReply = parsedInnerContent.reply;
              }
            } else {
              incomingContent = typeof data.content === 'string' ? data.content : JSON.stringify(data, null, 2);
            }
          } else if (data.content) {
            incomingContent = data.content;
          }
        } catch (e) {
          incomingContent = dataStr;
          nodeName = "model";
        }

        if (incomingContent) {
          const currentSessions = { ...props.sessions };
          const sessionData = currentSessions[sessionKey] ? [...currentSessions[sessionKey]] : [];

          if (nodeName !== lastNodeName || currentAiMsgIndex === -1) {
            lastNodeName = nodeName;
            
            sessionData.push({ 
              role: 'assistant', 
              content: incomingContent,
              node: nodeName,
              isNewStep: true 
            });
            currentAiMsgIndex = sessionData.length - 1;

            if (isJsonNode && extractedReply) {
              sessionData.push({
                role: 'assistant',
                content: extractedReply,
                node: 'reply', 
                isNewStep: true
              });
            }
          } else {
            if (currentAiMsgIndex !== -1 && sessionData[currentAiMsgIndex]) {
              const targetMsg = { ...sessionData[currentAiMsgIndex] };
              
              if (isJsonNode) {
                targetMsg.content = incomingContent; 
                sessionData[currentAiMsgIndex] = targetMsg;
                
                const nextMsgIndex = currentAiMsgIndex + 1;
                if (extractedReply && sessionData[nextMsgIndex] && sessionData[nextMsgIndex].node === 'reply') {
                  sessionData[nextMsgIndex].content = extractedReply;
                } else if (extractedReply && (!sessionData[nextMsgIndex] || sessionData[nextMsgIndex].node !== 'reply')) {
                  sessionData.splice(nextMsgIndex, 0, {
                    role: 'assistant',
                    content: extractedReply,
                    node: 'reply',
                    isNewStep: true
                  });
                }
              } else {
                targetMsg.content += incomingContent;
                sessionData[currentAiMsgIndex] = targetMsg;
              }
            }
          }
          
          currentSessions[sessionKey] = sessionData;
          emit('update:sessions', currentSessions);
          
          await nextTick();
          scrollToBottom();
        }
      }
    }
  } catch (error: any) {
    const errSessions = { ...props.sessions };
    const sessionData = errSessions[sessionKey] ? [...errSessions[sessionKey]] : [];
    sessionData.push({ role: 'assistant', content: `❌ 错误: ${error.message}`, node: 'Error' });
    errSessions[sessionKey] = sessionData;
    emit('update:sessions', errSessions);
  } finally {
    isTyping.value = false;
    await nextTick();
    scrollToBottom();
  }
};

const scrollToBottom = async () => {
  await nextTick();
  if (scrollRef.value) scrollRef.value.scrollTop = scrollRef.value.scrollHeight;
};
</script>

<template>
  <div class="ai_chat_container">
    <!-- 顶部导航栏 -->
    <div class="top_bar">
      <div class="agent_tabs">
        <!-- ⚡ 修改点：将点击事件直接绑定给具备双向回传特性的 currentAgentId 计算属性 -->
        <div 
          v-for="agent in agents" 
          :key="agent.id"
          :class="['tab_item', currentAgentId === agent.id ? 'active' : '']"
          @click="currentAgentId = agent.id"
        >
          {{ agent.name }}
        </div>
      </div>
      
      <!-- 线程控制器 -->
      <div class="thread_controls">
        <select class="thread_selector" v-model="currentThreadId">
          <option v-for="tid in historyThreads" :key="tid" :value="tid">
            对话: {{ tid }}
          </option>
        </select>
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
        :class="['msg_row', msg.role === 'user' ? 'row_user' : 'row_ai', msg.isNewStep ? 'new_step_animation' : '']"
      >
        <div class="avatar">{{ msg.role === 'user' ? 'ME' : 'AI' }}</div>
        
        <div class="content_box">
          <div v-if="msg.role === 'assistant' && msg.node" class="node_tag">
            <template v-if="msg.node === 'tools'">⚙️ 工具输出 (原始数据)</template>
            <template v-else-if="msg.node === 'reply'">📋 提取结论</template>
            <template v-else-if="msg.node === 'model'">🤖 AI 文本回复</template>
            <template v-else>⚡ 步骤: {{ msg.node }}</template>
          </div>
          
          <div class="markdown_body">
            <vue-markdown 
              :source="formatMarkdownSource(msg)" 
              v-if="msg.content" 
            />
            <p v-else-if="isTyping && index === chatList.length - 1">正在处理...</p>
          </div>
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
      }
    }

    .thread_controls {
      display: flex;
      align-items: center;
      gap: 12px;
      
      .thread_selector {
        background: rgba(0, 15, 30, 0.8);
        border: 1px solid rgba(49, 171, 227, 0.4);
        color: rgba(255, 255, 255, 0.8);
        font-family: monospace;
        font-size: 12px;
        padding: 4px 8px;
        border-radius: 4px;
        outline: none;
        cursor: pointer;
        transition: 0.3s;
        
        &:hover, &:focus {
          border-color: #00fdfa;
          box-shadow: 0 0 5px rgba(0, 253, 250, 0.2);
          color: #fff;
        }

        option {
          background: #000f1e;
          color: #31ABE3;
        }
      }

      .new_btn {
        background: transparent;
        border: 1px dashed #00fdfa;
        color: #00fdfa;
        padding: 4px 10px;
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

      .avatar { width: 32px; height: 32px; border-radius: 8px; font-size: 10px; line-height: 32px; text-align: center; flex-shrink: 0; }
      
      .content_box {
        max-width: 85%;
        padding: 10px 14px;
        border-radius: 8px;
        font-size: 13.5px;
        transition: all 0.3s ease;

        .node_tag { 
          font-size: 10px; 
          color: #00fdfa; 
          margin-bottom: 6px; 
          font-weight: bold; 
          background: rgba(49, 171, 227, 0.15); 
          padding: 2px 6px; 
          border-radius: 4px; 
          display: inline-block; 
        }

        .markdown_body {
          word-break: break-word;
          color: #e0e0e0;
          :deep(p) { margin: 0 0 8px 0; &:last-child { margin-bottom: 0; } }
          :deep(code) { color: #f07178; background: rgba(240, 113, 120, 0.1); padding: 2px 4px; border-radius: 3px; }
          :deep(pre) { background: #050a0f; padding: 10px; border-radius: 6px; overflow-x: auto; margin: 10px 0; border: 1px solid rgba(49, 171, 227, 0.2); }
        }
      }
    }

    .row_ai {
      .avatar { background: #31ABE3; color: #fff; margin-right: 12px; }
      .content_box { background: rgba(49, 171, 227, 0.08); border: 1px solid rgba(49, 171, 227, 0.2); }
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

.new_step_animation {
  animation: stepFadeIn 0.4s ease-out forwards;
}

@keyframes stepFadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>