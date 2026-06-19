<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount } from "vue";

// ── Props（来自父组件 index.vue，作为数据源之一） ──
const props = defineProps<{
  sessions?: Record<string, any[]>;
  agentId?: string;
}>();

// ── 常量 ──
const SSKEY = "wazuh_all_sessions";
const TMKEY = "wazuh_agent_thread_map";
const DEFAULT_AGENT = props.agentId || "router_agent";

// ── 状态 ──
const currentThreadId = ref("加载中...");
const userMessageCount = ref(0);
const copied = ref(false);

// ── 数据刷新（优先使用 localStorage 以保证跨页面实时同步） ──
const refreshData = () => {
  // 1. 读取当前线程 ID
  const threadMap: Record<string, string> = JSON.parse(
    localStorage.getItem(TMKEY) || "{}"
  );
  const tid = threadMap[DEFAULT_AGENT] || "";
  currentThreadId.value = tid || "暂无活跃会话";

  // 2. 统计当前会话的用户消息数
  if (tid) {
    const key = `${DEFAULT_AGENT}_${tid}`;
    let messages: any[] = [];

    // 优先从 props 读取（实时性最高），fallback 到 localStorage
    if (props.sessions && props.sessions[key]) {
      messages = props.sessions[key];
    } else {
      const allSessions: Record<string, any[]> = JSON.parse(
        localStorage.getItem(SSKEY) || "{}"
      );
      messages = allSessions[key] || [];
    }

    userMessageCount.value = messages.filter(
      (m: any) => m.role === "user"
    ).length;
  } else {
    userMessageCount.value = 0;
  }
};

// ── 线程 ID 截断显示 ──
const truncatedId = computed(() => {
  const id = currentThreadId.value;
  if (!id || id === "暂无活跃会话" || id === "加载中...") return id;
  return id.length > 22
    ? id.substring(0, 10) + "..." + id.substring(id.length - 8)
    : id;
});

// ── 复制线程 ID ──
const copyThreadId = async () => {
  if (
    !currentThreadId.value ||
    currentThreadId.value === "暂无活跃会话" ||
    currentThreadId.value === "加载中..."
  )
    return;
  try {
    await navigator.clipboard.writeText(currentThreadId.value);
    copied.value = true;
    setTimeout(() => {
      copied.value = false;
    }, 2000);
  } catch {
    // 降级：选中文本
  }
};

// ── 导航到第二页 AI 对话 ──
const navigateToAIChat = () => {
  window.dispatchEvent(new CustomEvent("navigate-to-ai-chat"));
};

// ── 轮询刷新（保证跨页面数据同步） ──
let refreshTimer: any = null;

onMounted(() => {
  refreshData();
  refreshTimer = setInterval(refreshData, 3000);
});

onBeforeUnmount(() => {
  if (refreshTimer) clearInterval(refreshTimer);
});
</script>

<template>
  <div class="ai-monitor-panel">
    <!-- 当前线程 ID -->
    <div class="info-card">
      <div class="info-label">
        <span class="info-icon">🧵</span>
        <span>当前线程 ID</span>
      </div>
      <div class="info-value-row">
        <span class="thread-id" :class="{ 'thread-id--empty': currentThreadId === '暂无活跃会话' || currentThreadId === '加载中...' }">
          {{ truncatedId }}
        </span>
        <button
          class="copy-btn"
          :class="{ 'copy-btn--done': copied }"
          :disabled="currentThreadId === '暂无活跃会话' || currentThreadId === '加载中...'"
          :title="copied ? '已复制' : '复制到剪贴板'"
          @click="copyThreadId"
        >
          {{ copied ? "✓" : "📋" }}
        </button>
      </div>
    </div>

    <!-- 已发送消息计数 -->
    <div class="info-card">
      <div class="info-label">
        <span class="info-icon">💬</span>
        <span>已发送消息</span>
      </div>
      <div class="count-value">{{ userMessageCount }}</div>
      <div class="info-footer">当前会话用户消息总数</div>
    </div>

    <!-- 导航按钮 -->
    <button class="nav-btn" @click="navigateToAIChat">
      <span class="nav-btn-bg"></span>
      <span class="nav-btn-content">
        <span class="nav-btn-icon">➤</span>
        <span>前往 AI 终端</span>
      </span>
    </button>

    <!-- 状态栏 -->
    <!-- 111111 -->
  </div>
</template>

<style scoped lang="scss">
.ai-monitor-panel {
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 14px;
  height: 100%;
  box-sizing: border-box;
}

// ── 信息卡片 ──
.info-card {
  background: var(--card, #ffffff);
  border: 1px solid var(--border, #e5e7eb);
  border-radius: 8px;
  padding: 14px 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  transition: border-color 0.2s;

  &:hover {
    border-color: rgba(49, 171, 227, 0.3);
  }
}

.info-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-weight: 500;
  color: var(--muted-foreground, #7c8a9e);

  .info-icon {
    font-size: 14px;
    line-height: 1;
  }
}

.info-value-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

// ── 线程 ID ──
.thread-id {
  font-family: "Consolas", "Fira Code", monospace;
  font-size: 13px;
  color: #1d4ed8;
  letter-spacing: 0.5px;
  text-shadow: none;
  user-select: all;

  &--empty {
    color: var(--muted-foreground, #7c8a9e);
    text-shadow: none;
    user-select: none;
  }
}

// ── 复制按钮 ──
.copy-btn {
  width: 32px;
  height: 32px;
  border: 1px solid rgba(49, 171, 227, 0.2);
  border-radius: 6px;
  background: rgba(49, 171, 227, 0.06);
  color: #31abe3;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;

  &:hover:not(:disabled) {
    background: rgba(49, 171, 227, 0.16);
    border-color: #31abe3;
    box-shadow: 0 0 10px rgba(49, 171, 227, 0.15);
  }

  &:disabled {
    opacity: 0.3;
    cursor: not-allowed;
  }

  &--done {
    background: rgba(29, 78, 216, 0.1);
    border-color: #1d4ed8;
    color: #1d4ed8;
  }
}

// ── 消息计数 ──
.count-value {
  font-family: "Consolas", "Fira Code", monospace;
  font-size: 24px;
  font-weight: 400;
  color: #31abe3;
  text-shadow: 0 0 20px rgba(49, 171, 227, 0.2);
  line-height: 1.1;
}

.info-footer {
  font-size: 0px;
  color: var(--muted-foreground, #7c8a9e);
  opacity: 0.5;
  font-family: ui-monospace, monospace;
  letter-spacing: 0.3px;
}

// ── 导航按钮（霓虹科技风） ──
.nav-btn {
  position: relative;
  width: 50%;
  margin: 0 auto;
  padding: 4px 10px;
  background: transparent;
  border: 1px solid rgba(49, 171, 227, 0.25);
  border-radius: 6px;
  cursor: pointer;
  overflow: hidden;
  transition: all 0.35s ease;
  flex-shrink: 0;

  .nav-btn-bg {
    position: absolute;
    inset: 0;
    background: linear-gradient(
      135deg,
      rgba(49, 171, 227, 0.08),
      rgba(0, 253, 250, 0.04)
    );
    transition: opacity 0.35s ease;
  }

  .nav-btn-content {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    z-index: 1;

    .nav-btn-icon {
      font-size: 12px;
      color: #00fdfa;
      transition: transform 0.35s ease;
    }

    span:last-child {
      font-size: 11px;
      font-weight: 600;
      color: #31abe3;
      letter-spacing: 0.5px;
      transition: color 0.35s ease;
    }
  }

  &:hover {
    border-color: #31abe3;
    box-shadow:
      0 0 16px rgba(49, 171, 227, 0.18),
      inset 0 0 16px rgba(49, 171, 227, 0.05);

    .nav-btn-bg {
      background: linear-gradient(
        135deg,
        rgba(49, 171, 227, 0.14),
        rgba(0, 253, 250, 0.08)
      );
    }

    .nav-btn-content {
      .nav-btn-icon {
        transform: translateX(4px);
      }

      span:last-child {
        color: #00fdfa;
        text-shadow: 0 0 8px rgba(0, 253, 250, 0.3);
      }
    }
  }

  &:active {
    transform: scale(0.97);
  }
}

// ── 状态栏 ──
.status-bar {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  flex-shrink: 0;
  margin-top: auto;
}

.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #07f7a8;
  animation: pulse-dot 2s ease-in-out infinite;
}

.status-text {
  font-size: 10px;
  color: var(--muted-foreground, #7c8a9e);
  opacity: 0.4;
  letter-spacing: 0.3px;
}

@keyframes pulse-dot {
  0%,
  100% {
    opacity: 0.3;
  }
  50% {
    opacity: 1;
  }
}
</style>
