<script setup lang="ts">
import { ref, computed, onMounted } from "vue";
import { ElMessage } from "element-plus";
import axios from 'axios';

// ── Wazuh 认证配置 ──
const wazuhUser = import.meta.env.VITE_WAZUH_SERVER_API_USERNAME;
const wazuhPass = import.meta.env.VITE_WAZUH_SERVER_API_PASSWORD;
const AUTH_PAYLOAD = btoa(`${wazuhUser}:${wazuhPass}`);
const token = ref("");

// ── 🎯 目标监控主机（内部状态，通过下拉框切换）──
const currentAgentId = ref("");
const currentAgentName = ref("");

// ── 可用主机列表（用于下拉选择器）──
const availableAgents = ref<any[]>([]);
const loadingAgents = ref(false);

// ── 数据与分页状态 ──
const allProcesses = ref<any[]>([]); // 存储拉取到的所有进程
const loading = ref(false);
const pageSize = ref(15);         // 对应你截图中的 Rows per page: 15
const currentPage = ref(1);

// ── 详情弹窗状态 ──
const detailVisible = ref(false);
const selectedProcessRaw = ref("");

// ── 计算属性：纯前端分页计算 ──
const tableData = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value;
  const end = start + pageSize.value;
  return allProcesses.value.slice(start, end);
});

const totalItems = computed(() => allProcesses.value.length);

// ── 核心方法：获取认证 Token ──
const authenticate = async () => {
  try {
    const res = await axios.get('/wazuh-api/security/user/authenticate', {
      headers: { 'Authorization': `Basic ${AUTH_PAYLOAD}` }
    });
    token.value = res.data.data.token;
    return true;
  } catch (err) {
    ElMessage.error("Wazuh 认证失败");
    return false;
  }
};

// ── 核心方法：获取可用主机列表 ──
const fetchAgents = async () => {
  if (!token.value) {
    const success = await authenticate();
    if (!success) return;
  }

  loadingAgents.value = true;
  try {
    const res = await axios.get('/wazuh-api/agents', {
      headers: { 'Authorization': `Bearer ${token.value}` },
      params: { limit: 500, sort: '+id' }
    });
    availableAgents.value = res.data.data?.affected_items || [];

    // 默认选中第一台在线主机
    const firstActive = availableAgents.value.find((a: any) => a.status === 'active');
    if (firstActive) {
      currentAgentId.value = String(firstActive.id);
      currentAgentName.value = firstActive.name;
    } else if (availableAgents.value.length > 0) {
      currentAgentId.value = String(availableAgents.value[0].id);
      currentAgentName.value = availableAgents.value[0].name;
    }
  } catch (err: any) {
    ElMessage.error("获取主机列表失败: " + err.message);
  } finally {
    loadingAgents.value = false;
  }
};

// ── 核心方法：获取指定主机的进程数据 ──
const fetchProcesses = async (isRetry = false) => {
  if (!currentAgentId.value) {
    console.warn("[Wazuh] 尚未选择主机，暂不发送请求。");
    return;
  }

  if (!token.value) {
    const success = await authenticate();
    if (!success) return;
  }

  loading.value = true;

  try {
    // 调用 Wazuh 的 syscollector 进程监控接口
    // limit: 1000 用于一次性拉取，避免被 Wazuh 默认的 50 条限制撑爆
    const res = await axios.get(`/wazuh-api/syscollector/${currentAgentId.value}/processes`, {
      headers: { 'Authorization': `Bearer ${token.value}` },
      params: { limit: 1000 }
    });

    allProcesses.value = res.data.data?.affected_items || [];
  } catch (err: any) {
    if (err.response?.status === 401 && !isRetry) {
      token.value = "";
      await fetchProcesses(true); // 401 自动重试认证
    } else {
      ElMessage.error(`获取主机 [${currentAgentName.value}] 进程列表失败: ` + err.message);
    }
  } finally {
    loading.value = false;
  }
};

// ── 切换选中主机时重新拉取进程 ──
const onAgentChange = (agentId: string) => {
  const agent = availableAgents.value.find((a: any) => String(a.id) === agentId);
  if (agent) {
    currentAgentId.value = String(agent.id);
    currentAgentName.value = agent.name;
    currentPage.value = 1;
    fetchProcesses();
  }
};

// ── 处理时间戳显示 ──
const formatProcessTime = (timeObj: any) => {
  if (!timeObj) return '-';
  if (typeof timeObj === 'string') return timeObj;
  return timeObj.start || '-';
};

// ── 处理每页条数改变 ──
const handleSizeChange = (val: number) => {
  pageSize.value = val;
  currentPage.value = 1;
};

// ── 处理页码改变 ──
const handleCurrentChange = (val: number) => {
  currentPage.value = val;
};

// ── 展示单条进程的原始 JSON 详情弹窗 ──
const showDetail = (proc: any) => {
  selectedProcessRaw.value = JSON.stringify(proc, null, 2);
  detailVisible.value = true;
};

// ── 复制 JSON 到剪贴板 ──
const copyToClipboard = (text: string) => {
  navigator.clipboard.writeText(text).then(() => {
    ElMessage.success("进程 JSON 已复制");
  });
};

onMounted(() => {
  fetchAgents();  // 拉取主机列表 → 自动选中第一台在线主机 → 拉取其进程
});
</script>

<template>
  <div class="tg-root flex flex-col h-full">
    <!-- ── 工具栏：标题 + 主机选择器 + 刷新 ── -->
    <div class="tg-toolbar flex items-center justify-between flex-shrink-0 px-4 py-3">
      <div class="flex items-center gap-3">
        <span class="text-sm font-bold text-[#31ABE3]">📊 系统进程监控</span>
        <!-- 主机下拉选择器 -->
        <div class="agent-selector-group">
          <span class="text-xs text-[#7c8a9e] mr-1">主机</span>
          <select
            class="agent-select"
            :value="currentAgentId"
            @change="onAgentChange(($event.target as HTMLSelectElement).value)"
            :disabled="loadingAgents"
          >
            <option value="" disabled>
              {{ loadingAgents ? '正在加载主机列表…' : '-- 请选择主机 --' }}
            </option>
            <option
              v-for="agent in availableAgents"
              :key="agent.id"
              :value="String(agent.id)"
            >
              #{{ agent.id }} {{ agent.name }} ({{ agent.ip }})
            </option>
          </select>
        </div>
        <span v-if="currentAgentName" class="agent-badge font-mono">📌 {{ currentAgentName }}</span>
      </div>
      <div class="flex items-center gap-2">
        <button class="refresh-btn" @click="fetchProcesses(false)" :disabled="loading || !currentAgentId">🔄 刷新数据</button>
        <span class="text-xs text-[#7c8a9e]">共运行 {{ totalItems }} 个进程</span>
      </div>
    </div>

    <!-- ── 进程列表表头 ── -->
    <div
      v-if="totalItems > 0"
      class="al-list-header grid grid-cols-[2fr_1fr_0.8fr_0.8fr_4fr_60px] gap-2 px-4 py-2.5 text-xs font-semibold flex-shrink-0"
    >
      <span>进程名称</span>
      <span>启动时间</span>
      <span>PID</span>
      <span>父进程 PID</span>
      <span>命令行</span>
      <span class="text-center">操作</span>
    </div>

    <!-- ── 进程列表数据行 ── -->
    <div
      class="al-list-body flex-1 overflow-y-auto px-4"
      v-loading="loading"
      element-loading-background="rgba(255, 255, 255, 0.6)"
    >
      <div v-if="totalItems === 0 && !loading" class="hq-empty">
        <template v-if="!currentAgentId">请在上方选择要监控的主机</template>
        <template v-else>暂无该主机的进程监控数据（请检查 syscollector 模块是否开启）</template>
      </div>

      <div class="al-list-scroll">
        <div
          v-for="(proc, index) in tableData"
          :key="index"
          class="al-row grid grid-cols-[2fr_1fr_0.8fr_0.8fr_4fr_60px] gap-2 px-2 py-2 rounded-md transition-all duration-200"
        >
          <!-- 进程名称 -->
          <span class="text-xs truncate font-bold text-[#1e293b] flex items-center gap-1">
            📄 {{ proc.name || '-' }}
          </span>
          <!-- 启动时间 -->
          <span class="text-xs truncate font-mono text-[#64748b]">
            {{ formatProcessTime(proc.format_time || proc.start_time) }}
          </span>
          <!-- PID -->
          <span class="text-xs truncate font-mono text-[#0f172a] font-semibold">{{ proc.pid || '-' }}</span>
          <!-- 父进程 PID -->
          <span class="text-xs truncate font-mono text-[#64748b]">{{ proc.ppid || '-' }}</span>
          <!-- 命令行 -->
          <span class="text-xs truncate font-mono text-[#334155] cmd-box" :title="proc.cmd || proc.command">
            {{ proc.cmd || proc.command || '-' }}
          </span>
          <!-- 操作 -->
          <span class="flex items-center justify-center">
            <button class="al-action-btn" title="查看原始进程 JSON" @click="showDetail(proc)">···</button>
          </span>
        </div>
      </div>
    </div>

    <!-- ── 分页条 ── -->
    <div class="pagination-bar flex-shrink-0">
      <span class="pagination-info">共 {{ totalItems }} 条进程</span>
      <div class="pagination-controls">
        <div class="page-size-group">
          <span>每页</span>
          <select
            :value="pageSize"
            @change="handleSizeChange(Number(($event as any).target.value))"
            class="page-size-select"
          >
            <option :value="15">15</option>
            <option :value="30">30</option>
            <option :value="50">50</option>
            <option :value="100">100</option>
          </select>
          <span>条</span>
        </div>
        <div class="page-nav-group">
          <button
            class="pg-btn"
            :disabled="currentPage <= 1"
            @click="handleCurrentChange(currentPage - 1)"
          >‹</button>
          <span class="page-info font-mono">{{ currentPage }} / {{ Math.ceil(totalItems / pageSize) || 1 }}</span>
          <button
            class="pg-btn"
            :disabled="currentPage >= Math.ceil(totalItems / pageSize)"
            @click="handleCurrentChange(currentPage + 1)"
          >›</button>
        </div>
      </div>
    </div>

    <!-- ── 原始 JSON 详情弹窗 ── -->
    <Teleport to="body">
      <div v-if="detailVisible" class="modal-mask" @click.self="detailVisible = false">
        <div class="modal-panel">
          <div class="modal-header">
            <h3 class="text-sm font-bold text-[#31ABE3] m-0">该进程原始明细 JSON</h3>
            <div class="flex items-center gap-2">
              <button class="modal-btn modal-btn--copy" @click="copyToClipboard(selectedProcessRaw)">复制 JSON</button>
              <button class="modal-btn modal-btn--close" @click="detailVisible = false">关闭</button>
            </div>
          </div>
          <div class="modal-body">
            <pre class="modal-pre">{{ selectedProcessRaw }}</pre>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped lang="scss">
/* ══════════════════════════════════════════════════════════════
   进程数据展示面板 · 视觉设计完全承袭原样本规范
   ══════════════════════════════════════════════════════════════ */

.tg-root {
  background: #ffffff;
  border-radius: 8px;
  border: 1px solid #e5e7eb;
  position: relative;
  overflow: hidden;
  height: 100%;
}

.tg-toolbar {
  border-bottom: 1px solid #e5e7eb;
  background: #f8fafc;
}

// 主机名微章
.agent-badge {
  font-size: 11px;
  background: #f1f5f9;
  border: 1px solid #cbd5e1;
  color: #475569;
  padding: 2px 8px;
  border-radius: 4px;
}

// 主机选择器
.agent-selector-group {
  display: flex;
  align-items: center;
}

.agent-select {
  background: #ffffff;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  padding: 3px 8px;
  font-size: 12px;
  color: #374151;
  outline: none;
  cursor: pointer;
  font-family: ui-monospace, monospace;
  min-width: 220px;
  max-width: 300px;

  &:focus {
    border-color: rgba(49, 171, 227, 0.3);
    box-shadow: 0 0 0 2px rgba(49, 171, 227, 0.06);
  }

  &:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
}

// 刷新按钮
.refresh-btn {
  background: #ffffff;
  border: 1px solid #d1d5db;
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 11px;
  color: #374151;
  cursor: pointer;
  transition: all 0.2s;
  &:hover:not(:disabled) {
    border-color: #31ABE3;
    color: #31ABE3;
    background: rgba(49, 171, 227, 0.04);
  }
  &:disabled { opacity: 0.5; cursor: not-allowed; }
}

.al-list-header {
  background: #f8fafc;
  color: #7c8a9e;
  border-bottom: 1px solid #e5e7eb;

  > span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
}

.al-list-body {
  position: relative;
  overflow-y: auto;

  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb {
    background: rgba(124, 138, 158, 0.15);
    border-radius: 2px;
  }
}

.al-row {
  border-bottom: 1px solid rgba(229, 231, 235, 0.5);
  min-height: 38px;
  align-items: center;

  &:hover {
    background: rgba(49, 171, 227, 0.04);
  }

  &:last-child {
    border-bottom: none;
  }

  > * {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
}

// 命令行参数灰色轻量背景框
.cmd-box {
  background: #f8fafc;
  border: 1px solid #f1f5f9;
  padding: 2px 6px;
  border-radius: 4px;
  color: #334155;
}

.al-action-btn {
  background: transparent;
  border: none;
  cursor: pointer;
  font-size: 13px;
  padding: 2px;
  opacity: 0.5;
  transition: opacity 0.2s;
  line-height: 1;
  flex-shrink: 0;

  &:hover {
    opacity: 1;
  }
}

.hq-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  font-size: 12px;
  color: #7c8a9e;
  opacity: 0.5;
  text-align: center;
  padding: 40px 20px;
}

/* 分页条控制 */
.pagination-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 16px;
  border-top: 1px solid #e5e7eb;
  background: #f8fafc;
}

.pagination-info {
  font-size: 12px;
  color: #7c8a9e;
  white-space: nowrap;
}

.pagination-controls {
  display: flex;
  align-items: center;
  gap: 16px;
}

.page-size-group {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: #7c8a9e;
}

.page-size-select {
  background: #ffffff;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  padding: 3px 8px;
  font-size: 12px;
  color: #374151;
  outline: none;
  cursor: pointer;
  font-family: ui-monospace, monospace;

  &:focus {
    border-color: rgba(49, 171, 227, 0.3);
    box-shadow: 0 0 0 2px rgba(49, 171, 227, 0.06);
  }
}

.page-nav-group {
  display: flex;
  align-items: center;
  gap: 4px;
}

.page-info {
  padding: 0 8px;
  font-size: 12px;
  color: #7c8a9e;
}

.pg-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 28px;
  height: 26px;
  padding: 0 8px;
  font-size: 13px;
  font-weight: 500;
  color: #7c8a9e;
  background: transparent;
  border: 1px solid rgba(49, 171, 227, 0.12);
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s ease;
  user-select: none;
  line-height: 1;

  &:hover:not(:disabled) {
    color: #31ABE3;
    border-color: rgba(49, 171, 227, 0.3);
    background: rgba(49, 171, 227, 0.06);
  }

  &:disabled {
    opacity: 0.35;
    cursor: not-allowed;
  }
}

/* Modal 遮罩与细节弹窗 */
.modal-mask {
  position: fixed;
  inset: 0;
  background: rgba(255, 255, 255, 0.9);
  backdrop-filter: blur(4px);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 9999;
}

.modal-panel {
  width: 75%;
  max-height: 85vh;
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 20px;
    border-bottom: 1px solid #e5e7eb;
  }

  .modal-body {
    flex: 1;
    min-height: 0;
    overflow: auto;
    padding: 16px 20px;
  }

  .modal-pre {
    margin: 0;
    color: #374151;
    font-family: 'Courier New', ui-monospace, monospace;
    font-size: 12.5px;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.6;
  }
}

.modal-btn {
  padding: 5px 14px;
  font-size: 12px;
  font-weight: 600;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s ease;
  border: none;

  &--copy {
    background: transparent;
    border: 1px solid rgba(49, 171, 227, 0.12);
    color: #31ABE3;
    &:hover { background: rgba(49, 171, 227, 0.1); }
  }

  &--close {
    background: #31ABE3;
    color: #fff;
    &:hover { background: #00fdfa; color: #000; }
  }
}

:deep(.el-loading-text) {
  color: #7c8a9e;
}
</style>