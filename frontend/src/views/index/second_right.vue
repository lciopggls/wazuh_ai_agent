<script setup lang="ts">
import { ref, onMounted, nextTick, computed, watch } from "vue";
import VueMarkdown from 'vue-markdown-render';

// --- 1. 配置与状态定义 ---
const props = defineProps<{
  sessions: Record<string, any[]>;
}>();

const emit = defineEmits(['update:sessions']);

const agents = [
  { id: 'router_agent', name: '路由智能体' },
  { id: 'attack_attribution', name: '攻击溯源' }
];

// 当前选中的智能体 ID
const currentAgentId = ref("attack_attribution");

// 智能体与线程 ID 的映射表
const agentThreadMap = ref<Record<string, string>>(
  JSON.parse(localStorage.getItem('wazuh_agent_thread_map') || '{}')
);

const userInput = ref("");
const isTyping = ref(false);
const scrollRef = ref<HTMLElement | null>(null);

// --- 💡 弹窗状态管理 ---
const isModalOpen = ref(false);
const activeModalData = ref<any>(null);

// --- 2. 计算属性 ---

// 获取当前智能体的所有历史线程 ID
const historyThreads = computed(() => {
  const prefix = `${currentAgentId.value}_`;
  return Object.keys(props.sessions)
    .filter(key => key.startsWith(prefix))
    .map(key => key.replace(prefix, ''));
});

// 获取当前活跃的线程 ID（带保护，防止切换时为空）
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
  
  // 纯净的深拷贝一层，维护单向数据流
  const updatedSessions = { ...props.sessions };
  updatedSessions[newKey] = [];
  
  emit('update:sessions', updatedSessions);
};

// --- 4. 核心发送与流式渲染逻辑 ---

const handleSend = async () => {
  if (!userInput.value.trim() || isTyping.value) return;

  const msg = userInput.value;
  const aid = currentAgentId.value;
  const tid = currentThreadId.value;
  const sessionKey = `${aid}_${tid}`;

  // 严格遵循规范：不直接操作 props.sessions 内层数组
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

      // === 修改后的前端 chunk 循环处理逻辑 ===
for (const line of lines) {
  if (line.startsWith('data: ')) {
    const dataStr = line.replace('data: ', '').trim();
    if (dataStr === '[DONE]') break;

    // 定义提取出来的变量
    let incomingContent = "";
    let nodeName = lastNodeName || "Processing_Node";

    try {
      const data = JSON.parse(dataStr);
      nodeName = data.node || lastNodeName || "Agent_Node";
      
      // 1. 通用提取：优先取 content，取不到再尝试转义整个对象或取其它常见键
      if (data.content) {
        incomingContent = data.content;
      } else if (nodeName === 'Attack_Abstract_Node') {
        const copy = { ...data };
        delete copy.node; delete copy.content;
        if (Object.keys(copy).length > 0) incomingContent = JSON.stringify(copy, null, 2);
      } else {
        // 💡 核心增强：如果后端把数据塞在别的地方，尝试将其整体序列化输出，不丢弃数据
        const copy = { ...data };
        delete copy.node;
        if (Object.keys(copy).length > 0) {
          incomingContent = copy.output || copy.messages || JSON.stringify(copy);
        }
      }
    } catch (e) {
      // 2. 💡 通用兜底：如果后端吐出来的压根不是 JSON 字符串（而是纯文本），直接当成文本渲染
      incomingContent = dataStr;
    }

    // 3. 统一渲染气泡（移除特定节点的硬编码限制）
    if (incomingContent) {
      if (typeof incomingContent === 'object' && incomingContent !== null) {
        incomingContent = JSON.stringify(incomingContent, null, 2);
      }

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
      } else {
        if (currentAiMsgIndex !== -1 && sessionData[currentAiMsgIndex]) {
          const targetMsg = { ...sessionData[currentAiMsgIndex] };
          targetMsg.content += incomingContent;
          sessionData[currentAiMsgIndex] = targetMsg;
        }
      }
      
      currentSessions[sessionKey] = sessionData;
      emit('update:sessions', currentSessions);
      
      await nextTick();
      scrollToBottom();
    }
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

// 辅助函数：在展现层处理不同节点的内容包装
const formatMessageContent = (msg: any) => {
  if (msg.node === 'Attack_Abstract_Node' && msg.content) {
    // 检查是否已经包裹过，防止意外重复
    if (msg.content.startsWith('```json')) return msg.content;
    return `\`\`\`json\n${msg.content}\n\`\`\``;
  }
  return msg.content;
};

// --- 💡 处理点击卡片：解析 JSON 数据并开启弹窗 ---
const handleNodeClick = (msg: any) => {
  if (msg.node !== 'Attack_Abstract_Node') return;
  try {
    // 处理各种边界情况，确保拿到纯净的 json 进行渲染
    let rawContent = msg.content || "";
    if (typeof rawContent === 'string') {
      rawContent = rawContent.replace(/```json\n?|```/g, '').trim();
    }
    
    const parsed = typeof rawContent === 'object' ? rawContent : JSON.parse(rawContent);
    
    // 计算指标总数，供弹窗顶部表格使用
    const iocTotal = (parsed.ioc_files?.length || 0) + (parsed.ioc_domains?.length || 0) + (parsed.ioc_processes?.length || 0);
    
    activeModalData.value = {
      ...parsed,
      total_hosts: parsed.hosts?.length || 0,
      total_iocs: iocTotal,
      total_tactics: parsed.tactics_count || parsed.tactics?.length || 0
    };
    isModalOpen.value = true;
  } catch (e) {
    console.error("解析攻击摘要 JSON 失败:", e);
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
        
        <!-- 💡 消息核心区：如果是摘要节点，增加点击交互提示 -->
        <div 
          class="content_box" 
          :class="{ 'abstract_node_box_clickable': msg.node === 'Attack_Abstract_Node' }"
          @click="handleNodeClick(msg)"
          :title="msg.node === 'Attack_Abstract_Node' ? '点击查看可视化溯源摘要' : ''"
        >
          <div v-if="msg.role === 'assistant' && msg.node" class="node_tag">
            ⚡ 步骤: {{ msg.node }} 
            <span v-if="msg.node === 'Attack_Abstract_Node'" class="click_tip">🖱️ 点击查看大图</span>
          </div>
          
          <!-- Markdown 渲染 -->
          <div class="markdown_body">
            <vue-markdown :source="formatMessageContent(msg)" v-if="msg.content" />
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

    <!-- 💡 SOC 科技风溯源调查摘要弹窗 -->
    <div v-if="isModalOpen" class="modal_overlay" @click.self="isModalOpen = false">
      <div class="soc_modal_card">
        <div class="modal_close" @click="isModalOpen = false">×</div>
        <h2 class="modal_title">攻击溯源调查摘要</h2>
        
        <!-- 核心指标指标栏 (四格表) -->
        <table class="metrics_table">
          <thead>
            <tr>
              <th>涉及主机</th>
              <th>时间跨度</th>
              <th>IOC 总数</th>
              <th>战术阶段</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td class="highlight_blue">{{ activeModalData.total_hosts }} 台</td>
              <td class="highlight_blue">{{ activeModalData.duration || '0时0分0秒' }}</td>
              <td class="highlight_cyan">{{ activeModalData.total_iocs }} 个</td>
              <td class="highlight_cyan">{{ activeModalData.total_tactics }} 个</td>
            </tr>
          </tbody>
        </table>

        <!-- 详细卡片信息展现 -->
        <div class="detail_section">
          <div class="section_title">涉及主机：描述涉及的主机名</div>
          <ul class="detail_list">
            <li v-for="host in activeModalData.hosts" :key="host">
              <span class="bullet_icon">📌</span> {{ host }}
            </li>
            <li v-if="!activeModalData.hosts || activeModalData.hosts.length === 0" class="empty_item">无主机记录</li>
          </ul>

          <div class="section_title">时间跨度：给出攻击跨越的时间</div>
          <ul class="detail_list">
            <li>
              <span class="bullet_icon">⏰</span> {{ activeModalData.start_time || 'N/A' }} - {{ activeModalData.end_time || 'N/A' }}
            </li>
          </ul>

          <div class="section_title">涉及 IOC：依次列出文件名、域名、进程名</div>
          <div class="sub_detail_group">
            <!-- 文件夹类型 -->
            <div class="sub_label">文件：</div>
            <ul class="detail_list text_indent">
              <li v-for="file in activeModalData.ioc_files" :key="file">
                <span class="bullet_icon">📄</span> {{ file }}
              </li>
              <li v-if="!activeModalData.ioc_files || activeModalData.ioc_files.length === 0" class="empty_sub_item">无相关文件 IOC</li>
            </ul>
            
            <!-- 域名和IP -->
            <div class="sub_label">IP / 域名：</div>
            <ul class="detail_list text_indent">
              <li v-for="domain in activeModalData.ioc_domains" :key="domain">
                <span class="bullet_icon">🌐</span> {{ domain }}
              </li>
              <li v-if="!activeModalData.ioc_domains || activeModalData.ioc_domains.length === 0" class="empty_sub_item">无相关网络/域名 IOC</li>
            </ul>

            <!-- 关联进程 -->
            <div class="sub_label">进程：</div>
            <ul class="detail_list text_indent">
              <li v-for="proc in activeModalData.ioc_processes" :key="proc">
                <span class="bullet_icon">⚙️</span> {{ proc }}
              </li>
              <li v-if="!activeModalData.ioc_processes || activeModalData.ioc_processes.length === 0" class="empty_sub_item">无关联进程</li>
            </ul>
          </div>

          <div class="section_title">ATT&CK 战术覆盖：依次列出所有的 tactics</div>
          <ul class="detail_list tactic_tags">
            <li v-for="tactic in activeModalData.tactics" :key="tactic">
              <span class="bullet_icon">🛡️</span> {{ tactic }}
            </li>
            <li v-if="!activeModalData.tactics || activeModalData.tactics.length === 0" class="empty_item">无匹配战术</li>
          </ul>
        </div>
      </div>
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
          .click_tip {
            margin-left: 8px;
            color: #ffaa00;
            text-decoration: underline;
          }
        }
        
        // 目标可点击节点专属样式：增加微弱的发光渐变及手势
        &.abstract_node_box_clickable {
          background: rgba(0, 253, 250, 0.03) !important;
          border: 1px dashed rgba(0, 253, 250, 0.4) !important;
          cursor: pointer;
          
          &:hover {
            background: rgba(0, 253, 250, 0.08) !important;
            border-color: #00fdfa !important;
            box-shadow: inset 0 0 12px rgba(0, 253, 250, 0.15), 0 0 8px rgba(0, 253, 250, 0.15);
          }
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

// ==========================================
// 💡 全新深度整合：科技蓝 SOC 弹窗样式表
// ==========================================
.modal_overlay {
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0, 10, 20, 0.8);
  backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 999;
  animation: modalFadeIn 0.25s ease-out;
}

.soc_modal_card {
  width: 90%;
  max-width: 650px;
  background: linear-gradient(180deg, rgba(0, 15, 30, 0.95) 0%, rgba(1, 7, 15, 0.98) 100%);
  border: 1.5px solid rgba(49, 171, 227, 0.6);
  box-shadow: 0 0 25px rgba(49, 171, 227, 0.4), inset 0 0 15px rgba(0, 253, 250, 0.1);
  border-radius: 10px;
  padding: 24px;
  position: relative;
  color: #e0e8f0;
  font-family: Consolas, Monaco, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  max-height: 85vh;
  overflow-y: auto;

  &::-webkit-scrollbar { width: 5px; }
  &::-webkit-scrollbar-thumb { background: rgba(49, 171, 227, 0.5); border-radius: 3px; }

  .modal_close {
    position: absolute;
    top: 15px; right: 20px;
    font-size: 24px;
    color: #31ABE3;
    cursor: pointer;
    transition: color 0.2s;
    &:hover { color: #00fdfa; }
  }

  .modal_title {
    text-align: center;
    font-size: 19px;
    font-weight: bold;
    color: #ffffff;
    letter-spacing: 2px;
    margin-top: 0;
    margin-bottom: 22px;
    text-shadow: 0 0 8px rgba(49, 171, 227, 0.7);
  }

  // 顶部核心四格统计表
  .metrics_table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 22px;
    border: 1px solid rgba(49, 171, 227, 0.25);

    th {
      background: rgba(49, 171, 227, 0.12);
      color: #31ABE3;
      font-size: 13px;
      padding: 8px;
      font-weight: 600;
      border: 1px solid rgba(49, 171, 227, 0.25);
    }

    td {
      text-align: center;
      padding: 12px 8px;
      font-size: 15px;
      font-weight: bold;
      border: 1px solid rgba(49, 171, 227, 0.25);
      background: rgba(0, 15, 30, 0.5);
    }

    // 适配科技感颜色规范
    .highlight_blue {
      color: #31ABE3;
      text-shadow: 0 0 4px rgba(49, 171, 227, 0.5);
    }

    .highlight_cyan {
      color: #00fdfa;
      text-shadow: 0 0 4px rgba(0, 253, 250, 0.5);
    }
  }

  // 信息分块展现
  .detail_section {
    .section_title {
      font-size: 14px;
      color: #55b6e6;
      font-weight: bold;
      margin-top: 20px;
      margin-bottom: 10px;
      border-left: 3px solid #00fdfa;
      padding-left: 8px;
    }

    .sub_label {
      font-size: 12px;
      color: rgba(49, 171, 227, 0.85);
      margin-top: 8px;
      margin-left: 12px;
      font-weight: bold;
    }

    .detail_list {
      list-style: none;
      padding-left: 12px;
      margin: 4px 0 10px 0;

      li {
        font-size: 13px;
        line-height: 1.6;
        color: #d1e2f0;
        margin-bottom: 5px;
        word-break: break-all;
        display: flex;
        align-items: flex-start;

        .bullet_icon {
          margin-right: 6px;
          flex-shrink: 0;
        }
      }

      .empty_item {
        color: rgba(255, 255, 255, 0.25);
        font-style: italic;
        font-size: 12px;
      }

      &.text_indent {
        padding-left: 24px;
        .empty_sub_item {
          color: rgba(255, 255, 255, 0.2);
          font-style: italic;
          font-size: 12px;
          list-style: none;
        }
      }

      // 战术标签样式
      &.tactic_tags {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        padding-left: 8px;
        li {
          background: rgba(0, 253, 250, 0.05);
          border: 1px solid rgba(0, 253, 250, 0.3);
          color: #00fdfa;
          padding: 3px 10px;
          border-radius: 4px;
          font-size: 12px;
          box-shadow: 0 0 5px rgba(0, 253, 250, 0.1);
        }
      }
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

@keyframes modalFadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}
</style>