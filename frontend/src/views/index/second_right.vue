<script setup lang="ts">
import { ref, onMounted, nextTick, computed, watch } from "vue";
import VueMarkdown from 'vue-markdown-render';
import {
  listAgents as listScoringAgents,
  listTestCases as listScoringTestCases,
  saveAndRegisterChatReport,
  type AgentSummary,
  type TestCaseSummary,
} from "@/api/report_scoring";
import { hasFinalAttributionReportHeading } from "./report-scoring/presentation";

type AgentOption = {
  id: string;
  name: string;
};

const DEFAULT_AGENT_OPTIONS: AgentOption[] = [
  { id: "router_agent", name: "路由智能体" },
];

// --- 1. 配置与状态定义 ---
// ⚡ 修改点：将 agentId 提升为从父组件传入，便于全局共享当前选中状态
const props = defineProps<{
  sessions: Record<string, any[]>;
  agentId: string; 
  agentOptions?: AgentOption[];
  storageNamespace?: string;
  enableReportScoringActions?: boolean;
}>();

const emit = defineEmits(['update:sessions', 'update:agentId']);

const agents = props.agentOptions?.length ? props.agentOptions : DEFAULT_AGENT_OPTIONS;
const defaultAgentId = agents[0]?.id || "router_agent";
const storageNamespace = props.storageNamespace || "production";
const storageKeys = storageNamespace === "production"
  ? {
      sessions: "wazuh_all_sessions",
      agentThreadMap: "wazuh_agent_thread_map",
    }
  : {
      sessions: `wazuh_${storageNamespace}_sessions`,
      agentThreadMap: `wazuh_${storageNamespace}_agent_thread_map`,
    };
const reportScoringActionsEnabled =
  import.meta.env.VITE_ENABLE_REPORT_SCORING === 'true' &&
  props.enableReportScoringActions === true;

// 当前活跃智能体（基于 prop 的计算属性，切换时通知父组件）
const currentAgentId = computed({
  get: () => props.agentId || defaultAgentId,
  set: (val: string) => emit('update:agentId', val)
});

// 智能体与线程 ID 的映射表（本地持久化）
const agentThreadMap = ref<Record<string, string>>(
  JSON.parse(localStorage.getItem(storageKeys.agentThreadMap) || '{}')
);

const userInput = ref("");
const isTyping = ref(false);
const scrollRef = ref<HTMLElement | null>(null);
const visualizationRequested = ref(false);

// --- 报告下载状态追踪（按消息索引） ---
const downloadStates = ref<Record<number, 'idle' | 'saving' | 'saved' | 'error'>>({});
const registrationStates = ref<Record<number, 'idle' | 'saving' | 'saved' | 'error'>>({});
const scoringCases = ref<TestCaseSummary[]>([]);
const scoringAgents = ref<AgentSummary[]>([]);
const registrationDialogVisible = ref(false);
const registrationDialogIndex = ref(-1);
const registrationDialogContent = ref("");
const registrationCaseId = ref("");
const registrationAgentId = ref("");
const includeCurrentThread = ref(true);
const registrationRunId = ref("");
const registrationNote = ref("");
const registrationError = ref("");

/** 判断气泡内容是否为攻击溯源报告 */
function isReportContent(msg: any): boolean {
  if (msg.role !== 'assistant' || !['reply', 'final_report'].includes(msg.node)) return false;
  const content = getMessageContent(msg);
  return msg.node === 'final_report' || hasFinalAttributionReportHeading(content);
}

/** 下载报告：调用后端 API 保存到指定目录 */
async function downloadReport(msg: any, index: number) {
  const content = getMessageContent(msg);
  if (!content) return;

  downloadStates.value[index] = 'saving';
  try {
    const response = await fetch('http://127.0.0.1:8001/api/report/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    });
    const result = await response.json();
    if (result.status === 'ok') {
      downloadStates.value[index] = 'saved';
      setTimeout(() => {
        if (downloadStates.value[index] === 'saved') {
          downloadStates.value[index] = 'idle';
        }
      }, 3000);
    } else {
      downloadStates.value[index] = 'error';
      setTimeout(() => { downloadStates.value[index] = 'idle'; }, 3000);
    }
  } catch (err: any) {
    console.error('保存报告失败:', err);
    downloadStates.value[index] = 'error';
    setTimeout(() => { downloadStates.value[index] = 'idle'; }, 3000);
  }
}

async function openScoringRegistration(msg: any, index: number) {
  registrationError.value = "";
  registrationDialogIndex.value = index;
  registrationDialogContent.value = getMessageContent(msg);
  registrationDialogVisible.value = true;
  try {
    if (!scoringCases.value.length || !scoringAgents.value.length) {
      [scoringCases.value, scoringAgents.value] = await Promise.all([
        listScoringTestCases(),
        listScoringAgents(),
      ]);
    }
    if (!registrationCaseId.value && scoringCases.value.length) {
      registrationCaseId.value = scoringCases.value[0].test_case_id;
    }
    if (!registrationAgentId.value && scoringAgents.value.length) {
      registrationAgentId.value = scoringAgents.value[0].agent_id;
    }
  } catch (error: any) {
    registrationError.value = `${error?.code || "REQUEST_FAILED"}: ${error?.message || String(error)}`;
  }
}

function closeScoringRegistration() {
  if (registrationStates.value[registrationDialogIndex.value] === 'saving') return;
  registrationDialogVisible.value = false;
}

async function submitScoringRegistration() {
  const index = registrationDialogIndex.value;
  if (index < 0 || !registrationCaseId.value || !registrationAgentId.value) return;
  registrationStates.value[index] = 'saving';
  registrationError.value = "";
  try {
    await saveAndRegisterChatReport({
      content: registrationDialogContent.value,
      scoring_registration: {
        test_case_id: registrationCaseId.value,
        agent_id: registrationAgentId.value,
        ...(includeCurrentThread.value && currentThreadId.value
          ? { thread_id: currentThreadId.value }
          : {}),
        ...(registrationRunId.value.trim() ? { run_id: registrationRunId.value.trim() } : {}),
        ...(registrationNote.value.trim() ? { note: registrationNote.value.trim() } : {}),
      },
    });
    registrationStates.value[index] = 'saved';
    registrationDialogVisible.value = false;
    setTimeout(() => {
      if (registrationStates.value[index] === 'saved') registrationStates.value[index] = 'idle';
    }, 3000);
  } catch (error: any) {
    registrationStates.value[index] = 'error';
    registrationError.value = `${error?.code || "REQUEST_FAILED"}: ${error?.message || String(error)}`;
  }
}

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
    localStorage.setItem(storageKeys.agentThreadMap, JSON.stringify(agentThreadMap.value));
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
    localStorage.setItem(storageKeys.agentThreadMap, JSON.stringify(agentThreadMap.value));
  }
});

// 监听智能体切换，确保线程安全跟随
watch(currentAgentId, (newAgentId) => {
  if (!agentThreadMap.value[newAgentId]) {
    initAgentThread(newAgentId);
    localStorage.setItem(storageKeys.agentThreadMap, JSON.stringify(agentThreadMap.value));
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
  localStorage.removeItem(storageKeys.sessions);
  localStorage.removeItem(storageKeys.agentThreadMap);

  // 重置本地线程映射状态
  agentThreadMap.value = {};

  // 通知父组件清空会话数据，前端视图立即同步为空状态
  emit('update:sessions', {});

  // 为当前智能体创建一个新的默认线程，保证界面可继续使用
  initAgentThread(currentAgentId.value);
  localStorage.setItem(storageKeys.agentThreadMap, JSON.stringify(agentThreadMap.value));
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

  // ⚡ 本地会话累加器：脏数据路径中多个段共享同一份 session 状态
  //    避免 processDataObject 每次从 stale 的 props.sessions 拷贝
  let streamSessionData: any[] = [...(props.sessions[sessionKey] || [])];
  // ⚡ SSE 行缓冲：处理 TCP 分片跨越 data: 行边界的情况
  let lineBuffer = '';

  try {
    const response = await fetch('http://127.0.0.1:8001/api/chat/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: msg,
        thread_id: tid,
        agent_id: aid,
        visualization_requested: visualizationRequested.value,
      })
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

      // ⚡ 使用 streamSessionData 本地累加器替代每次都从 props.sessions 拷贝
      //    确保同一 chunk 内多个 data 行操作始终基于最新的流状态
      if (nodeName !== lastNodeName || currentAiMsgIndex === -1) {
        // ── 新步骤（切换 Node 类型或首次进入 → 新建气泡） ──
        lastNodeName = nodeName;
        streamSessionData.push({
          role: 'assistant',
          content: incomingContent,
          node: nodeName,
          isNewStep: true,
        });
        currentAiMsgIndex = streamSessionData.length - 1;

        if (isJsonNode && extractedReply) {
          streamSessionData.push({
            role: 'assistant',
            content: extractedReply,
            node: 'reply',
            isNewStep: true,
          });
        }
      } else {
        // ── 追加到当前步骤（同一 Node 类型 → 流式累加） ──
        if (currentAiMsgIndex !== -1 && streamSessionData[currentAiMsgIndex]) {
          const targetMsg = { ...streamSessionData[currentAiMsgIndex] };

          if (isJsonNode) {
            targetMsg.content = incomingContent;
            streamSessionData[currentAiMsgIndex] = targetMsg;

            const nextIdx = currentAiMsgIndex + 1;
            if (extractedReply && streamSessionData[nextIdx]?.node === 'reply') {
              streamSessionData[nextIdx].content = extractedReply;
            } else if (extractedReply) {
              streamSessionData.splice(nextIdx, 0, {
                role: 'assistant',
                content: extractedReply,
                node: 'reply',
                isNewStep: true,
              });
            }
          } else {
            targetMsg.content += incomingContent;
            streamSessionData[currentAiMsgIndex] = targetMsg;
          }
        }
      }

      // 用本地累加器构建最新状态发射出去
      emit('update:sessions', { ...props.sessions, [sessionKey]: streamSessionData });
    };

    // ⚡ 辅助函数：对单条 data 字符串尝试 JSON.parse → 失败则走脏数据容错路径
    const processDataStr = (dataStr: string) => {
      try {
        const data = JSON.parse(dataStr);
        processDataObject(data);
        return; // 干净数据 → 直接返回
      } catch {
        // 脏数据：走下面的容错路径
      }
      // 脏数据路径：text + JSON 混合 → 分段提取
      const segments = findJsonSegmentsInText(dataStr);
      for (const seg of segments) {
        if (seg.type === 'json') {
          try {
            const data = JSON.parse(seg.content);
            processDataObject(data);
          } catch {
            if (seg.content.trim()) {
              processDataObject({ node: 'model', content: seg.content });
            }
          }
        } else if (seg.content.trim()) {
          processDataObject({ node: 'model', content: seg.content });
        }
      }
    };

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      const chunk = decoder.decode(value, { stream: true });
      const allText = lineBuffer + chunk;
      const lines = allText.split('\n');

      // ⚡ SSE 行缓冲：处理 TCP 分片跨越 data: 行边界
      //   - 以 \n 结尾 → 最后一项是空串，弹出；buffer 清空
      //   - 不以 \n 结尾 → 最后一项不完整，放入 buffer 等下一块
      if (allText.endsWith('\n')) {
        lines.pop();
        lineBuffer = '';
      } else {
        lineBuffer = lines.pop() || '';
      }

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const dataStr = line.replace('data: ', '').trim();
        if (dataStr === '[DONE]') break;
        processDataStr(dataStr);
        await nextTick();
        scrollToBottom();
      }
    }

    // ⚡ 流结束后，处理 buffer 中残留的不完整 data 行
    if (lineBuffer.startsWith('data: ')) {
      const dataStr = lineBuffer.replace('data: ', '').trim();
      if (dataStr && dataStr !== '[DONE]') {
        processDataStr(dataStr);
        await nextTick();
        scrollToBottom();
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
        <button
          type="button"
          :class="['visualization_toggle', { active: visualizationRequested }]"
          :aria-pressed="visualizationRequested"
          title="仅在新调查开始时读取该设置；调查开始后的切换不会影响当前调查。"
          @click="visualizationRequested = !visualizationRequested"
        >
          <span aria-hidden="true">{{ visualizationRequested ? '●' : '○' }}</span>
          启用可视化
        </button>
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
            <template v-else-if="msg.node === 'reply' || msg.node === 'final_report'">
              📋 提取结论
              <!-- 攻击溯源报告下载按钮 -->
              <button
                v-if="isReportContent(msg)"
                class="report_download_btn"
                :class="{
                  'report_download_btn--saving': downloadStates[index] === 'saving',
                  'report_download_btn--saved': downloadStates[index] === 'saved',
                  'report_download_btn--error': downloadStates[index] === 'error',
                }"
                :disabled="downloadStates[index] === 'saving'"
                @click.stop="downloadReport(msg, index)"
                :title="
                  downloadStates[index] === 'saving' ? '保存中...' :
                  downloadStates[index] === 'saved' ? '已保存 ✓' :
                  downloadStates[index] === 'error' ? '保存失败' :
                  '保存报告到本地'
                "
              >
                <template v-if="downloadStates[index] === 'saving'">⏳</template>
                <template v-else-if="downloadStates[index] === 'saved'">✅</template>
                <template v-else-if="downloadStates[index] === 'error'">❌</template>
                <template v-else>💾 下载报告</template>
              </button>
              <button
                v-if="reportScoringActionsEnabled && isReportContent(msg)"
                class="report_download_btn report_register_btn"
                :class="{
                  'report_download_btn--saving': registrationStates[index] === 'saving',
                  'report_download_btn--saved': registrationStates[index] === 'saved',
                  'report_download_btn--error': registrationStates[index] === 'error',
                }"
                :disabled="registrationStates[index] === 'saving'"
                title="选择已登记案例和被测智能体后，保存并登记到开发期评分工具"
                @click.stop="openScoringRegistration(msg, index)"
              >
                <template v-if="registrationStates[index] === 'saving'">⏳ 登记中</template>
                <template v-else-if="registrationStates[index] === 'saved'">✅ 已登记</template>
                <template v-else-if="registrationStates[index] === 'error'">❌ 重试登记</template>
                <template v-else>🧮 保存并登记评分</template>
              </button>
            </template>
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

  <teleport to="body">
    <div
      v-if="registrationDialogVisible"
      class="scoring_dialog_overlay"
      @click.self="closeScoringRegistration"
    >
      <div class="scoring_dialog">
        <header><h3>保存并登记评分报告</h3><button @click="closeScoringRegistration">✕</button></header>
        <p>请显式选择报告对应的测试案例和被测智能体。当前聊天智能体不会自动覆盖该选择。</p>
        <label>测试案例<select v-model="registrationCaseId"><option v-for="item in scoringCases" :key="item.test_case_id" :value="item.test_case_id">{{ item.display_name }} · {{ item.scoring_standard_version }}</option></select></label>
        <label>被测智能体<select v-model="registrationAgentId"><option v-for="item in scoringAgents" :key="item.agent_id" :value="item.agent_id">{{ item.display_name }}</option></select></label>
        <label class="checkbox"><input v-model="includeCurrentThread" type="checkbox" />附带当前 Thread ID：{{ currentThreadId || '无' }}</label>
        <label>Run ID（可选）<input v-model="registrationRunId" maxlength="160" /></label>
        <label>备注（可选）<input v-model="registrationNote" maxlength="1000" /></label>
        <div v-if="registrationError" class="scoring_dialog_error">{{ registrationError }}</div>
        <footer><button class="cancel" @click="closeScoringRegistration">取消</button><button :disabled="!registrationCaseId || !registrationAgentId || registrationStates[registrationDialogIndex] === 'saving'" @click="submitScoringRegistration">确认保存并登记</button></footer>
      </div>
    </div>
  </teleport>

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

      .visualization_toggle {
        background: transparent;
        border: 1px solid #6b7280;
        color: #4b5563;
        padding: 4px 10px;
        font-size: 12px;
        cursor: pointer;
        border-radius: 4px;
        transition: 0.2s;

        &.active {
          border-color: #1d4ed8;
          color: #1d4ed8;
          background: rgba(29, 78, 216, 0.05);
        }

        &:hover {
          border-color: #1d4ed8;
          color: #1d4ed8;
        }
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

// ── 报告下载按钮 ──
.report_download_btn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-left: 10px;
  padding: 2px 10px;
  font-size: 11px;
  font-weight: 600;
  color: #1d4ed8;
  background: rgba(29, 78, 216, 0.08);
  border: 1px solid rgba(29, 78, 216, 0.2);
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s ease;
  vertical-align: middle;
  line-height: 1.4;

  &:hover:not(:disabled) {
    background: rgba(29, 78, 216, 0.15);
    border-color: #1d4ed8;
    box-shadow: 0 0 8px rgba(29, 78, 216, 0.15);
  }

  &:disabled {
    cursor: not-allowed;
    opacity: 0.6;
  }

  &--saving {
    color: #f59e0b;
    border-color: #f59e0b;
    background: rgba(245, 158, 11, 0.08);
  }

  &--saved {
    color: #10b981;
    border-color: #10b981;
    background: rgba(16, 185, 129, 0.08);
  }

  &--error {
    color: #ef4444;
    border-color: #ef4444;
    background: rgba(239, 68, 68, 0.08);
  }
}

.report_register_btn {
  color: #7c3aed;
  border-color: rgba(124, 58, 237, 0.3);
  background: rgba(124, 58, 237, 0.08);

  &:hover:not(:disabled) {
    color: #6d28d9;
    border-color: #7c3aed;
    background: rgba(124, 58, 237, 0.14);
  }
}

.scoring_dialog_overlay {
  position: fixed;
  inset: 0;
  z-index: 1100;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(15, 23, 42, 0.48);
}

.scoring_dialog {
  width: min(520px, calc(100vw - 32px));
  padding: 20px;
  border-radius: 12px;
  background: #ffffff;
  box-shadow: 0 18px 48px rgba(15, 23, 42, 0.24);
  color: #334155;

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;

    h3 { margin: 0; color: #1e3a8a; }
    button { border: 0; background: transparent; color: #64748b; cursor: pointer; }
  }

  > p { color: #64748b; font-size: 12px; line-height: 1.6; }

  label {
    display: flex;
    flex-direction: column;
    gap: 5px;
    margin-top: 10px;
    color: #64748b;
    font-size: 12px;

    input, select {
      padding: 8px 10px;
      border: 1px solid #d1d5db;
      border-radius: 6px;
      background: #ffffff;
      color: #1f2937;
    }
  }

  label.checkbox {
    flex-direction: row;
    align-items: center;

    input { margin: 0; }
  }

  footer {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 18px;

    button {
      padding: 8px 13px;
      border: 0;
      border-radius: 6px;
      background: #7c3aed;
      color: #ffffff;
      cursor: pointer;

      &.cancel { background: #e2e8f0; color: #475569; }
      &:disabled { opacity: 0.45; cursor: not-allowed; }
    }
  }
}

.scoring_dialog_error {
  margin-top: 10px;
  padding: 8px 10px;
  border-radius: 6px;
  background: #fef2f2;
  color: #b91c1c;
  font-size: 12px;
  word-break: break-word;
}
</style>
