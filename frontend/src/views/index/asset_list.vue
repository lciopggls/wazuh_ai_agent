<script setup lang="ts">
import { ref, computed, onMounted } from "vue";
import { ElMessage } from "element-plus";
import axios from 'axios';

// ── Wazuh 认证配置 ──
const wazuhUser = import.meta.env.VITE_WAZUH_SERVER_API_USERNAME;
const wazuhPass = import.meta.env.VITE_WAZUH_SERVER_API_PASSWORD;
const AUTH_PAYLOAD = btoa(`${wazuhUser}:${wazuhPass}`);
const token = ref("");

// ── 数据与分页状态 ──
const allAgents = ref<any[]>([]); // 存储从后端拿到的所有资产
const loading = ref(false);
const pageSize = ref(50);         // 对应图中的 Rows per page: 50
const currentPage = ref(1);

// ── 详情弹窗状态 ──
const detailVisible = ref(false);
const selectedAgentRaw = ref("");

// ── 计算属性：纯前端计算当前页展示的数据，避开服务端的 400 参数限制 ──
const tableData = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value;
  const end = start + pageSize.value;
  return allAgents.value.slice(start, end);
});

const totalItems = computed(() => allAgents.value.length);

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

// ── 核心方法：获取 Agent 列表（100% 对齐你另一个可用组件的请求模式） ──
const fetchAgents = async (isRetry = false) => {
  if (!token.value) {
    const success = await authenticate();
    if (!success) return;
  }

  loading.value = true;
  const startTime = performance.now();

  try {
    // 移除所有 params 参数，防止代理层解析 query 字符串时触发 400 错误
    const res = await axios.get('/wazuh-api/agents', {
      headers: { 'Authorization': `Bearer ${token.value}` }
    });

    allAgents.value = res.data.data?.affected_items || [];
  } catch (err: any) {
    if (err.response?.status === 401 && !isRetry) {
      token.value = "";
      await fetchAgents(true); // 401 自动重试
    } else {
      ElMessage.error("获取受控资产列表失败: " + err.message);
    }
  } finally {
    loading.value = false;
    // 查询耗时统计：查询结束后弹出耗时提示
    const elapsed = performance.now() - startTime;
    const duration = elapsed >= 1000 ? `${(elapsed / 1000).toFixed(2)} s` : `${Math.round(elapsed)} ms`;
    ElMessage.info(`查询耗时 ${duration}`);
  }
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

// ── 根据不同状态返回对应的图标/颜色 ──
const getStatusDetails = (status: string) => {
  switch (status) {
    case 'active':
      return { color: '#10b981', text: 'active' };
    case 'disconnected':
      return { color: '#f59e0b', text: 'disconnected' };
    case 'pending':
      return { color: '#3b82f6', text: 'pending' };
    default:
      return { color: '#ef4444', text: status || 'unknown' };
  }
};

// ── 展示原始 JSON 详情弹窗 ──
const showDetail = (agent: any) => {
  selectedAgentRaw.value = JSON.stringify(agent, null, 2);
  detailVisible.value = true;
};

// ── 复制 JSON 到剪贴板 ──
const copyToClipboard = (text: string) => {
  navigator.clipboard.writeText(text).then(() => {
    ElMessage.success("JSON 已复制");
  });
};

onMounted(() => {
  fetchAgents();
});
</script>

<template>
  <div class="tg-root flex flex-col h-full">
    <!-- ── Toolbar：完全对齐 VulnerabilityQuery ── -->
    <div class="tg-toolbar flex items-center justify-between flex-shrink-0 px-4 py-3">
      <div class="flex items-center gap-2">
        <span class="text-sm font-bold text-[#31ABE3]">🖥️ 受控资产列表</span>
      </div>
      <span class="text-xs text-[#7c8a9e]">共 {{ totalItems }} 个资产</span>
    </div>

    <!-- ── 表格列标题 (CSS Grid，对齐 VulnerabilityQuery 的 al-list-header) ── -->
    <div
      v-if="totalItems > 0"
      class="al-list-header grid grid-cols-[60px_1.5fr_1fr_1fr_2fr_1fr_80px_90px_60px] gap-1 px-4 py-2.5 text-xs font-semibold flex-shrink-0"
    >
      <span class="text-center">主机ID</span>
      <span>主机名称</span>
      <span>主机IP</span>
      <span>Group</span>
      <span>操作系统</span>
      <span>集群节点</span>
      <span>版本</span>
      <span class="text-center">状态</span>
      <span class="text-center">操作</span>
    </div>

    <!-- ── 表格数据行 (CSS Grid，完全匹配表头列宽) ── -->
    <div
      class="al-list-body flex-1 overflow-y-auto px-4"
      v-loading="loading"
      element-loading-background="rgba(255, 255, 255, 0.6)"
    >
      <div v-if="totalItems === 0 && !loading" class="hq-empty">
        暂无受控资产数据
      </div>

      <div class="al-list-scroll">
        <div
          v-for="agent in tableData"
          :key="agent.id"
          class="al-row grid grid-cols-[60px_1.5fr_1fr_1fr_2fr_1fr_80px_90px_60px] gap-1 px-2 py-2.5 rounded-md transition-all duration-200"
        >
          <!-- ID -->
          <span class="text-center text-xs font-bold font-mono text-[#31ABE3]">
            {{ agent.id }}
          </span>
          <!-- Name -->
          <span class="text-xs truncate">{{ agent.name }}</span>
          <!-- IP address -->
          <span class="text-xs truncate font-mono text-[#7c8a9e]">{{ agent.ip }}</span>
          <!-- Group(s) -->
          <span class="text-xs truncate">
            <span
              v-for="group in agent.group"
              :key="group"
              class="al-group-tag"
            >{{ group }}</span>
          </span>
          <!-- Operating system -->
          <span class="text-xs truncate font-mono text-[#7c8a9e]">
            {{ agent.os?.name }} {{ agent.os?.version }}
          </span>
          <!-- Cluster node -->
          <span class="text-xs truncate font-mono text-[#7c8a9e]">
            {{ agent.node_name || 'node01' }}
          </span>
          <!-- Version -->
          <span class="text-xs truncate font-mono text-[#7c8a9e]">{{ agent.version }}</span>
          <!-- Status -->
          <span class="flex items-center justify-center gap-1.5">
            <span
              class="al-status-dot"
              :style="{ backgroundColor: getStatusDetails(agent.status).color }"
            ></span>
            <span class="al-status-text">{{ getStatusDetails(agent.status).text }}</span>
          </span>
          <!-- Actions -->
          <span class="flex items-center justify-center gap-1">
            <button class="al-action-btn" title="查看原始 JSON" @click="showDetail(agent)">···</button>
          </span>
        </div>
      </div>
    </div>

    <!-- ── 分页控件 (自定义样式，100% 对齐 VulnerabilityQuery 的分页条) ── -->
    <div class="pagination-bar flex-shrink-0">
      <span class="pagination-info">共 {{ totalItems }} 条</span>
      <div class="pagination-controls">
        <div class="page-size-group">
          <span>每页</span>
          <select
            :value="pageSize"
            @change="handleSizeChange(Number(($event as any).target.value))"
            class="page-size-select"
          >
            <option :value="10">10</option>
            <option :value="20">20</option>
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

    <!-- ── 原始 JSON 详情弹窗 (对齐 alerts_query / VulnerabilityQuery 弹窗规范) ── -->
    <Teleport to="body">
      <div v-if="detailVisible" class="modal-mask" @click.self="detailVisible = false">
        <div class="modal-panel">
          <div class="modal-header">
            <h3 class="text-sm font-bold text-[#31ABE3] m-0">受控资产原始 JSON</h3>
            <div class="flex items-center gap-2">
              <button class="modal-btn modal-btn--copy" @click="copyToClipboard(selectedAgentRaw)">复制 JSON</button>
              <button class="modal-btn modal-btn--close" @click="detailVisible = false">关闭</button>
            </div>
          </div>
          <div class="modal-body">
            <pre class="modal-pre">{{ selectedAgentRaw }}</pre>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped lang="scss">
/* ══════════════════════════════════════════════════════════════
   受控资产列表 · 视觉风格对齐第二页 VulnerabilityQuery 组件
   配色：   #31ABE3 (主题蓝)   #e5e7eb (边框)
           #f8fafc (表头/工具栏背景)  #7c8a9e (次要文字)
   字体：   12–13px   圆角：6–8px   间距体系：py-2.5 / px-4
   ══════════════════════════════════════════════════════════════ */

// ── 根容器 ──
.tg-root {
  background: #ffffff;
  border-radius: 8px;
  border: 1px solid #e5e7eb;
  position: relative;
  overflow: hidden;
  height: 100%;
}

// ── 工具栏 ──
.tg-toolbar {
  border-bottom: 1px solid #e5e7eb;
  background: #f8fafc;
}

// ── 列标题行 ──
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

// ── 表格主体 (滚动容器) ──
.al-list-body {
  position: relative;
  overflow-y: auto;

  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb {
    background: rgba(124, 138, 158, 0.15);
    border-radius: 2px;
  }
}

// ── 数据行 ──
.al-row {
  border-bottom: 1px solid rgba(229, 231, 235, 0.5);
  min-height: 40px;
  align-items: center;

  &:hover {
    background: rgba(49, 171, 227, 0.04);
  }

  &:last-child {
    border-bottom: none;
  }

  // 每个 grid 子项默认溢出省略
  > * {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
}

// ── 状态圆点 ──
.al-status-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  display: inline-block;
  flex-shrink: 0;
}

// ── 状态文字 ──
.al-status-text {
  font-family: ui-monospace, monospace;
  font-size: 11px;
  color: #334155;
}

// ── 分组标签 ──
.al-group-tag {
  display: inline-block;
  background: #ffffff;
  border: 1px solid #cbd5e1;
  color: #334155;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 10px;
  font-family: ui-monospace, monospace;
  margin-right: 2px;
  margin-bottom: 2px;
  line-height: 1.4;
}

// ── 操作按钮 ──
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

// ── 空状态 ──
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

// ══════════════════════════════════════════════
//  分页控件 · 100% 对齐 VulnerabilityQuery
// ══════════════════════════════════════════════

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

// ══════════════════════════════════════════════
//  Modal · 100% 对齐 alerts_query / VulnerabilityQuery
// ══════════════════════════════════════════════

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

// 覆盖 Element Plus v-loading 遮罩层的文字颜色
:deep(.el-loading-text) {
  color: #7c8a9e;
}
</style>