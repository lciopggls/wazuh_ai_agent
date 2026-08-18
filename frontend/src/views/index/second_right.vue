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

// --- 5. JSON 日志抽屉状态 ---
const drawerVisible = ref(false);
const drawerContent = ref("");
const drawerTitle = ref("");

/** 获取消息的原始文本内容 */
function getMessageContent(msg: any): string {
  if (!msg || !msg.content) return "";
  return typeof msg.content === 'string' ? msg.content : '';
}

/** 检测消息内容是否为 JSON 格式日志（尝试 JSON.parse） */
function isJsonContent(msg: any): boolean {
  const text = getMessageContent(msg).trim();
  if (!text) return false;
  const c = text[0];
  if (c !== '{' && c !== '[') return false;
  try {
    JSON.parse(text);
    return text.length > 30; // 避免将简短 JSON 对象误判为日志
  } catch {
    return false;
  }
}

function getJsonLogTitle(msg: any): string {
  if (msg.node === 'tools') return '⚙️ 工具输出日志';
  if (msg.role === 'user') return '📋 用户日志数据';
  return '📋 JSON 日志详情';
}

function openDrawer(msg: any) {
  const raw = getMessageContent(msg);
  try {
    const parsed = JSON.parse(raw);
    drawerContent.value = JSON.stringify(parsed, null, 2);
  } catch {
    drawerContent.value = raw;
  }
  drawerTitle.value = getJsonLogTitle(msg);
  drawerVisible.value = true;
}

function closeDrawer() {
  drawerVisible.value = false;
}

// --- 6. 用户消息 JSON 片段识别（混合 JSON+自然语言） ---

interface JsonSegment {
  type: 'json' | 'text';
  content: string;
}

/** 扫描文本，提取其中的 JSON 子串（对象/数组），与自然语言分离 */
function findJsonSegmentsInText(text: string): JsonSegment[] {
  const segments: JsonSegment[] = [];
  let lastIdx = 0;
  let i = 0;

  while (i < text.length) {
    if (text[i] === '{' || text[i] === '[') {
      const startChar = text[i];
      const endChar = startChar === '{' ? '}' : ']';
      let depth = 1;
      let inStr = false;
      let j = i + 1;

      while (j < text.length && depth > 0) {
        const ch = text[j];
        if (ch === '\\' && inStr) { j += 2; continue; }
        if (ch === '"') { inStr = !inStr; j++; continue; }
        if (!inStr) {
          if (ch === startChar) depth++;
          else if (ch === endChar) depth--;
        }
        j++;
      }

      if (depth === 0) {
        const candidate = text.slice(i, j);
        try {
          JSON.parse(candidate);
          // 有效 JSON → 保存前面的文本 + 该 JSON 片段
          if (i > lastIdx) {
            segments.push({ type: 'text', content: text.slice(lastIdx, i) });
          }
          segments.push({ type: 'json', content: candidate });
          lastIdx = j;
          i = j;
          continue;
        } catch {
          // 解析失败，继续往后扫描
        }
      }
    }
    i++;
  }

  // 剩余文本
  if (lastIdx < text.length) {
    segments.push({ type: 'text', content: text.slice(lastIdx) });
  }

  return segments;
}

/** 获取消息中的分段列表（仅对用户消息有意义） */
function getJsonSegments(msg: any): JsonSegment[] {
  const content = getMessageContent(msg);
  if (!content) return [];
  return findJsonSegmentsInText(content);
}

/** 判断消息是否包含 JSON 日志片段 */
function hasJsonSegments(msg: any): boolean {
  return getJsonSegments(msg).some(s => s.type === 'json');
}

function openDrawerWithContent(jsonContent: string) {
  try {
    const parsed = JSON.parse(jsonContent);
    drawerContent.value = JSON.stringify(parsed, null, 2);
  } catch {
    drawerContent.value = jsonContent;
  }
  drawerTitle.value = '📋 攻击日志详情';
  drawerVisible.value = true;
}

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

// 清除所有历史数据
const clearAllHistory = () => {
  if (!window.confirm('⚠️ 确定要清除所有历史对话数据吗？\n\n此操作会永久删除所有线程的聊天记录，且不可恢复！')) return;

  // 清空 localStorage 中持久化的会话数据
  localStorage.removeItem('wazuh_all_sessions');
  localStorage.removeItem('wazuh_agent_thread_map');

  // 重置本地线程映射状态
  agentThreadMap.value = {};

  // 通知父组件清空会话数据，前端视图立即同步为空状态
  emit('update:sessions', {});

  // 为当前智能体创建一个新的默认线程，保证界面可继续使用
  initAgentThread(currentAgentId.value);
  localStorage.setItem('wazuh_agent_thread_map', JSON.stringify(agentThreadMap.value));
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

    // ── 核心数据处理：将单个解析后的数据对象写入会话 ──
    // 闭包捕获 lastNodeName / currentAiMsgIndex / sessionKey
    const processDataObject = (data: any) => {
      let incomingContent = "";
      let nodeName = data.node || lastNodeName || "model";
      let isJsonNode = false;
      let extractedReply = "";

      // 工具节点 → 深度解析双重序列化的 content
      if (nodeName === 'tools') {
        isJsonNode = true;
        let parsedInnerContent: any = null;
        if (data.content) {
          try {
            parsedInnerContent = typeof data.content === 'string'
              ? JSON.parse(data.content)
              : data.content;
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
          incomingContent = typeof data.content === 'string'
            ? data.content
            : JSON.stringify(data, null, 2);
        }
      } else if (data.content) {
        incomingContent = data.content;
      }

      if (!incomingContent) return;

      const currentSessions = { ...props.sessions };
      const sessionData = currentSessions[sessionKey]
        ? [...currentSessions[sessionKey]]
        : [];

      if (nodeName !== lastNodeName || currentAiMsgIndex === -1) {
        // ── 新步骤 ──
        lastNodeName = nodeName;
        sessionData.push({
          role: 'assistant',
          content: incomingContent,
          node: nodeName,
          isNewStep: true,
        });
        currentAiMsgIndex = sessionData.length - 1;

        if (isJsonNode && extractedReply) {
          sessionData.push({
            role: 'assistant',
            content: extractedReply,
            node: 'reply',
            isNewStep: true,
          });
        }
      } else {
        // ── 追加到当前步骤 ──
        if (currentAiMsgIndex !== -1 && sessionData[currentAiMsgIndex]) {
          const targetMsg = { ...sessionData[currentAiMsgIndex] };

          if (isJsonNode) {
            // 工具节点 → 替换为最终格式化后的 JSON
            targetMsg.content = incomingContent;
            sessionData[currentAiMsgIndex] = targetMsg;

            const nextIdx = currentAiMsgIndex + 1;
            if (extractedReply && sessionData[nextIdx]?.node === 'reply') {
              sessionData[nextIdx].content = extractedReply;
            } else if (extractedReply) {
              sessionData.splice(nextIdx, 0, {
                role: 'assistant',
                content: extractedReply,
                node: 'reply',
                isNewStep: true,
              });
            }
          } else {
            // 文本节点 → 流式累加
            targetMsg.content += incomingContent;
            sessionData[currentAiMsgIndex] = targetMsg;
          }
        }
      }

      currentSessions[sessionKey] = sessionData;
      emit('update:sessions', currentSessions);
    };

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      const chunk = decoder.decode(value);
      const lines = chunk.split('\n');

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;

        const dataStr = line.replace('data: ', '').trim();
        if (dataStr === '[DONE]') break;

        // ─── 1) 标准 JSON 解析（数据干净时的快速路径） ───
        {
          let cleanParsed = false;
          try {
            const data = JSON.parse(dataStr);
            processDataObject(data);
            cleanParsed = true;
          } catch {
            // 脏数据：继续走容错路径
          }
          if (cleanParsed) {
            await nextTick();
            scrollToBottom();
            continue;
          }
        }

        // ─── 2) 脏数据容错：text + JSON 混合 → 分段提取 ───
        // 复用已有的 findJsonSegmentsInText 扫描混合文本中的 JSON 子串
        const segments = findJsonSegmentsInText(dataStr);
        for (const seg of segments) {
          if (seg.type === 'json') {
            try {
              const data = JSON.parse(seg.content);
              processDataObject(data);
            } catch {
              // 极低概率兜底（findJsonSegmentsInText 已验证过可解析）
              if (seg.content.trim()) {
                processDataObject({ node: 'model', content: seg.content });
              }
            }
          } else if (seg.content.trim()) {
            // 纯文本片段（例如 "好的，用户已确认线索…"）→ 作为 model 输出
            processDataObject({ node: 'model', content: seg.content });
          }
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
        <button @click="clearAllHistory" class="clear_btn">🗑 清除历史</button>
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

          <!-- ──── AI 消息渲染 ──── -->
          <template v-if="msg.role !== 'user'">
            <!-- AI 纯 JSON → 全量占位 -->
            <div v-if="isJsonContent(msg) && msg.content" class="json_log_placeholder" @click="openDrawer(msg)">
              <span class="json_log_icon">📋</span>
              <span class="json_log_label">AI-json回复</span>
              <span class="json_log_hint">点击查看详情 →</span>
            </div>
            <!-- AI 非 JSON → markdown -->
            <div v-else class="markdown_body">
              <vue-markdown
                :source="formatMarkdownSource(msg)"
                v-if="msg.content"
              />
              <p v-else-if="isTyping && index === chatList.length - 1">正在处理...</p>
            </div>
          </template>

          <!-- ──── 用户消息渲染 ──── -->
          <template v-else>
            <!-- 用户 混合 JSON+自然语言 → 分段渲染 -->
            <div v-if="hasJsonSegments(msg)" class="mixed_content">
              <template v-for="(seg, segIdx) in getJsonSegments(msg)" :key="segIdx">
                <span v-if="seg.type === 'text'" class="mixed_text_segment">{{ seg.content }}</span>
                <span v-else class="json_log_placeholder_inline" @click.stop="openDrawerWithContent(seg.content)">
                  📋 攻击日志 →
                </span>
              </template>
            </div>
            <!-- 用户 非 JSON → markdown（保持原样） -->
            <div v-else class="markdown_body">
              <vue-markdown :source="formatMarkdownSource(msg)" v-if="msg.content" />
            </div>
          </template>
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

  <!-- JSON 日志抽屉 -->
  <teleport to="body">
    <div v-if="drawerVisible" class="json_drawer_overlay" @click.self="closeDrawer">
      <div class="json_drawer_panel">
        <div class="json_drawer_header">
          <span class="json_drawer_title">{{ drawerTitle }}</span>
          <button class="json_drawer_close_btn" @click="closeDrawer">✕</button>
        </div>
        <div class="json_drawer_body">
          <pre class="json_drawer_content"><code>{{ drawerContent }}</code></pre>
        </div>
      </div>
    </div>
  </teleport>
</template>

<style scoped lang="scss">
.ai_chat_container {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  padding: 15px;
  overflow: hidden;
  position: relative;

  .top_bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 12px;
    border-bottom: 1px solid #e5e7eb;
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
        background: #ffffff;
        border: 1px solid #d1d5db;
        color: #374151;
        font-family: monospace;
        font-size: 12px;
        padding: 4px 8px;
        border-radius: 4px;
        outline: none;
        cursor: pointer;
        transition: 0.3s;
        
        &:hover, &:focus {
          border-color: #1d4ed8;
          box-shadow: 0 0 5px rgba(29, 78, 216, 0.2);
          color: #1f2937;
        }

        option {
          background: #ffffff;
          color: #374151;
        }
      }

      .new_btn {
        background: transparent;
        border: 1px dashed #1d4ed8;
        color: #1d4ed8;
        padding: 4px 10px;
        font-size: 12px;
        cursor: pointer;
        border-radius: 4px;
        &:hover { background: rgba(29, 78, 216, 0.05); }
      }

      .clear_btn {
        background: transparent;
        border: 1px solid #ef4444;
        color: #ef4444;
        padding: 4px 10px;
        font-size: 12px;
        cursor: pointer;
        border-radius: 4px;
        transition: 0.2s;
        &:hover { background: rgba(239, 68, 68, 0.06); }
      }
    }
  }

  .chat_window {
    flex: 1;
    overflow-y: auto;
    padding-right: 8px;
    margin-bottom: 15px;

    .empty_box { text-align: center; color: rgba(0,0,0,0.3); margin-top: 40px; font-size: 13px; }

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
          color: #1d4ed8;
          margin-bottom: 6px;
          font-weight: bold;
          background: rgba(29, 78, 216, 0.08);
          padding: 2px 6px;
          border-radius: 4px;
          display: inline-block;
        }

        .markdown_body {
          word-break: break-word;
          color: #374151;
          :deep(p) { margin: 0 0 8px 0; &:last-child { margin-bottom: 0; } }
          :deep(code) { color: #f07178; background: rgba(240, 113, 120, 0.1); padding: 2px 4px; border-radius: 3px; }
          :deep(pre) { background: #f3f4f6; padding: 10px; border-radius: 6px; overflow-x: auto; margin: 10px 0; border: 1px solid #e5e7eb; }
        }
      }
    }

    .row_ai {
      .avatar { background: #31ABE3; color: #fff; margin-right: 12px; }
      .content_box { background: #f0f7ff; border: 1px solid #bfdbfe; }
    }

    .row_user {
      flex-direction: row-reverse;
      .avatar { background: #00fdfa; color: #000; margin-left: 12px; }
      .content_box { background: #f0fdfa; border: 1px solid #bfdbfe; color: #1f2937; }
    }
  }

  .typing_indicator { font-size: 12px; color: #31ABE3; margin-bottom: 10px; font-style: italic; opacity: 0.8; }

  .input_area {
    display: flex;
    gap: 10px;
    height: 45px;
    input {
      flex: 1;
      background: #f9fafb;
      border: 1px solid #d1d5db;
      border-radius: 6px;
      color: #1f2937;
      padding: 0 15px;
      outline: none;
      &:focus { border-color: #1d4ed8; box-shadow: 0 0 5px rgba(29, 78, 216, 0.2); }
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

// ── JSON 日志交互占位（AI 消息全量占位） ──
.json_log_placeholder {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  background: #fef9e7;
  border: 1px solid #f9e79f;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
  user-select: none;

  &:hover {
    background: #fdebd0;
    border-color: #f5cba7;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  }

  .json_log_icon { font-size: 18px; }

  .json_log_label {
    font-size: 14px;
    font-weight: 600;
    color: #e67e22;
  }

  .json_log_hint {
    font-size: 12px;
    color: #95a5a6;
    margin-left: auto;
  }
}

// ── JSON 日志内联占位（用户消息混合内容） ──
.json_log_placeholder_inline {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  margin: 0 2px;
  background: #fef9e7;
  border: 1px solid #f9e79f;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
  font-weight: 600;
  color: #e67e22;
  transition: all 0.15s ease;
  user-select: none;
  white-space: nowrap;
  vertical-align: baseline;

  &:hover {
    background: #fdebd0;
    border-color: #f5cba7;
  }
}

// ── 用户消息混合内容容器 ──
.mixed_content {
  line-height: 1.6;

  .mixed_text_segment {
    font-size: 13.5px;
    color: inherit;
    word-break: break-word;
  }
}

// ── JSON 日志抽屉 ──
.json_drawer_overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
  background: rgba(0, 0, 0, 0.4);
  z-index: 1000;
  display: flex;
  justify-content: flex-end;
  animation: overlayFadeIn 0.2s ease;
}

.json_drawer_panel {
  width: min(680px, 85vw);
  height: 100vh;
  background: #ffffff;
  box-shadow: -4px 0 24px rgba(0, 0, 0, 0.18);
  display: flex;
  flex-direction: column;
  animation: slideInRight 0.25s ease-out;
}

.json_drawer_header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 24px;
  border-bottom: 1px solid #e5e7eb;
  flex-shrink: 0;

  .json_drawer_title {
    font-size: 16px;
    font-weight: 700;
    color: #1f2937;
  }

  .json_drawer_close_btn {
    width: 32px;
    height: 32px;
    border: none;
    background: #f3f4f6;
    border-radius: 6px;
    cursor: pointer;
    font-size: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #6b7280;
    transition: 0.2s;

    &:hover {
      background: #ef4444;
      color: #ffffff;
    }
  }
}

.json_drawer_body {
  flex: 1;
  overflow: auto;
  padding: 20px 24px;

  .json_drawer_content {
    margin: 0;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 13px;
    line-height: 1.7;
    color: #1f2937;
    white-space: pre-wrap;
    word-break: break-word;
  }
}

.new_step_animation {
  animation: stepFadeIn 0.4s ease-out forwards;
}

@keyframes stepFadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

@keyframes slideInRight {
  from { transform: translateX(100%); }
  to { transform: translateX(0); }
}

@keyframes overlayFadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}
</style>