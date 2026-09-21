<template>
  <div class="topo-container">
    <!-- 顶部状态栏 -->
    <div class="header">
      <div class="title">网络拓扑监控</div>
      <div class="status-info">
        <span class="dot active"></span> 运行中 (每30s刷新)
        <button @click="fetchTopoData" class="refresh-btn">立即刷新</button>
      </div>
    </div>

    <!-- 图表容器 -->
    <div ref="containerRef" class="x6-graph"></div>

    <!-- 底部图例 -->
    <div class="legend">
      <div class="item"><span class="legend-symbol manager"><img :src="serverIcon" alt="" /></span> 管理中心</div>
      <div class="item"><span class="legend-symbol active"><img :src="computerIcon" alt="" /></span> 在线主机</div>
      <div class="item"><span class="legend-symbol threat"><img :src="computerIcon" alt="" /></span> 近30分钟有高等级告警</div>
      <div class="item"><span class="legend-symbol offline"><img :src="computerIcon" alt="" /></span> 离线主机</div>
    </div>

    <!-- 加载遮罩 -->
    <div v-if="loading" class="loading-mask">数据加载中...</div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref, nextTick } from 'vue';
import { Graph } from '@antv/x6';
import axios from 'axios';
import serverIcon from '@/assets/img/topology/server.svg';
import computerIcon from '@/assets/img/topology/computer.svg';

// --- 配置区 ---
const TOPOLOGY_API_URL = import.meta.env.VITE_TOPOLOGY_API_URL?.trim() || 'http://127.0.0.1:8000/api/topo';
const TOPOLOGY_MOCK_URL = '/topology/agents_topo_data.json';
const REFRESH_INTERVAL = 30000; // 30秒自动刷新一次

// --- 文本与尺寸工具 ---
/** 10px 字体下每字符估算宽度 */
const CHAR_WIDTH = 6.2;
const NODE_PADDING = 20;
const MIN_NODE_WIDTH = 80;
const MAX_NODE_WIDTH = 240;

/** 根据 IP 长度估算节点宽度。 */
const calcNodeWidth = (ip: string): number => {
  return Math.max(MIN_NODE_WIDTH, Math.min(MAX_NODE_WIDTH, Math.round(ip.length * CHAR_WIDTH + NODE_PADDING)));
};

/** 节点宽度已达上限时，用省略号截断超长 IP。 */
const truncateText = (ip: string, maxW = MAX_NODE_WIDTH): string => {
  const maxChars = Math.floor((maxW - NODE_PADDING) / CHAR_WIDTH);
  return ip.length > maxChars ? ip.slice(0, Math.max(maxChars - 1, 1)) + '…' : ip;
};

const NODE_HEIGHT = 96;

/** 设备剪影为节点主体，圆形光环和状态灯表示运行状态。 */
const addDeviceNode = (id: string, x: number, y: number, width: number, icon: string, ip: string, color: string) => {
  const attrs = {
    body: { cx: width / 2, cy: 32, r: 31, fill: '#ffffff', stroke: color, strokeWidth: 3 },
    icon: { x: (width - 48) / 2, y: 8, width: 48, height: 48, xlinkHref: icon },
    status: { cx: width / 2 + 25, cy: 12, r: 6, fill: color, stroke: '#ffffff', strokeWidth: 2 },
    // X6 的 text 节点默认位于节点中心；这里的 x/y 是相对中心的偏移。
    ipText: { text: ip, x: 0, y: 27, textAnchor: 'middle', dominantBaseline: 'middle', fill: '#1f2937', fontSize: 11, fontWeight: 600 },
  };
  const existing = graph!.getNodes().find(node => node.id === id);
  if (existing) {
    // 刷新状态和 IP，保留用户拖动后的坐标及原有节点视图。
    if (existing.size().width !== width) existing.resize(width, NODE_HEIGHT);
    existing.attr(attrs);
    return;
  }
  graph!.addNode({
    id, x, y, width, height: NODE_HEIGHT,
    markup: [
      { tagName: 'circle', selector: 'body' },
      { tagName: 'image', selector: 'icon' },
      { tagName: 'circle', selector: 'status' },
      { tagName: 'text', selector: 'ipText' },
    ],
    attrs,
  });
};

const containerRef = ref<HTMLElement | null>(null);
const loading = ref(false);
let graph: Graph | null = null;
let timer: any = null;

// 1. 初始化画布
const initGraph = () => {
  if (!containerRef.value || graph) return;
  
  graph = new Graph({
    container: containerRef.value,
    autoResize: true,
    background: { color: '#DCE5FF' },
    panning: true, // 支持拖拽
    mousewheel: true, // 支持滚轮缩放
    grid: {
      size: 10,
      visible: true,
      type: 'dot',
      args: { color: '#e5e7eb', thickness: 1 },
    },
  });
};

// 2. 获取数据并渲染
const fetchTopoData = async () => {
  if (loading.value) return;
  loading.value = true;
  
  try {
    const res = await axios.get(TOPOLOGY_API_URL);
    renderTopology(res.data);
  } catch (err) {
    console.warn('实时拓扑接口不可用，回退到内置示例数据。', err);
    try {
      const mockRes = await axios.get(TOPOLOGY_MOCK_URL);
      renderTopology(mockRes.data);
    } catch (mockErr) {
      console.error("拓扑数据获取失败:", mockErr);
    }
  } finally {
    loading.value = false;
  }
};

// 3. 渲染逻辑
const renderTopology = (agents: any[]) => {
  if (!graph) return;
  const firstRender = graph.getNodes().length === 0;
  const activeNodeIds = new Set<string>();
  const activeEdgeIds = new Set<string>();
  // --- 布局参数 ---
  const centerX = containerRef.value?.clientWidth ? containerRef.value.clientWidth / 2 : 400;
  const startY = 80;
  const agentY = 250;
  const gapX = 180; // 节点横向间距

  // --- A. 绘制 Manager 节点 ---
  // 通常 127.0.0.1 或特定名称的是 Manager
  const managerData = agents.find(a => a.ip === '127.0.0.1' || a.name.toLowerCase().includes('manager'));
  const managerId = 'manager-node';

  const managerIp = String(managerData?.ip || '127.0.0.1');
  const managerNodeWidth = calcNodeWidth(managerIp);

  addDeviceNode(managerId, centerX - managerNodeWidth / 2, startY, managerNodeWidth, serverIcon, truncateText(managerIp), '#1890ff');
  activeNodeIds.add(managerId);

  // --- B. 绘制其他 Agents ---
  const otherAgents = agents.filter(a => a.ip !== '127.0.0.1' && !a.name.toLowerCase().includes('manager'));

  // 预计算所有节点的宽度，确保水平间距足够
  const agentWidths = otherAgents.map(a => calcNodeWidth(String(a.ip || 'unknown')));
  const maxAgentWidth = Math.max(0, ...agentWidths);
  const dynamicGapX = Math.max(gapX, maxAgentWidth + 30); // 节点边缘间至少保持 30px 间距

  // 计算总宽度以居中对齐
  const totalWidth = (otherAgents.length - 1) * dynamicGapX;
  const startX = centerX - totalWidth / 2;

  otherAgents.forEach((agent, index) => {
    const status = String(agent.status).toLowerCase();
    const hasThreat = agent.has_threat === true;

    // 颜色决策树
    let nodeColor = '#555'; // 默认灰色 (离线)
    if (hasThreat) {
      nodeColor = '#ff4d4f'; // 红色 (威胁)
    } else if (status === 'active') {
      nodeColor = '#52c41a'; // 绿色 (在线)
    }

    const nodeId = `agent-${agent.id}`;
    const edgeId = `manager-to-${agent.id}`;
    const nodeWidth = agentWidths[index];
    const displayIp = truncateText(String(agent.ip || 'unknown'));

    // 添加节点
    addDeviceNode(nodeId, startX + (index * dynamicGapX) - nodeWidth / 2, agentY, nodeWidth, computerIcon, displayIp, nodeColor);
    activeNodeIds.add(nodeId);

    // 只更新连线样式，避免刷新时重复生成连线。
    const line = {
      stroke: hasThreat ? '#ff4d4f' : '#444',
      strokeWidth: hasThreat ? 2 : 1,
      targetMarker: 'classic',
      dasharray: status !== 'active' ? '5 5' : '0', // 离线节点使用虚线
    };
    const existingEdge = graph!.getEdges().find(edge => edge.id === edgeId);
    if (existingEdge) {
      existingEdge.attr('line', line);
    } else {
      graph!.addEdge({ id: edgeId, source: managerId, target: nodeId, connector: { name: 'rounded' }, attrs: { line } });
    }
    activeEdgeIds.add(edgeId);
  });

  graph.getEdges().filter(edge => !activeEdgeIds.has(edge.id)).forEach(edge => graph!.removeEdge(edge));
  graph.getNodes().filter(node => !activeNodeIds.has(node.id)).forEach(node => graph!.removeNode(node));

  // 仅首次载入时居中，定时刷新不改变用户调整过的画布视角和节点位置。
  if (firstRender) nextTick(() => graph?.centerContent());
};

// --- 生命周期控制 ---
onMounted(() => {
  initGraph();
  fetchTopoData();
  
  // 启动定时轮询
  timer = setInterval(fetchTopoData, REFRESH_INTERVAL);
});

onUnmounted(() => {
  // 组件销毁时必须清理定时器
  if (timer) clearInterval(timer);
  if (graph) {graph.dispose();
              graph=null;
  }
});
</script>

<style scoped>
.topo-container {
  position: relative;
  width: 100%;
  height: 600px;
  background: #DCE5FF;
  border: 1px solid #e5e7eb;
  overflow: hidden;
  color: #374151;
  font-family: sans-serif;
}

.header {
  position: absolute;
  top: 0;
  width: 100%;
  padding: 15px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  z-index: 10;
  background: rgba(255, 255, 255, 0.95);
}

.title {
  font-size: 18px;
  font-weight: bold;
  letter-spacing: 1px;
}

.status-info {
  font-size: 12px;
  color: #6b7280;
}

.dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 5px;
}

.dot.active {
  background: #52c41a;
  box-shadow: 0 0 5px #52c41a;
}

.refresh-btn {
  margin-left: 10px;
  padding: 2px 8px;
  background: #1890ff;
  border: none;
  color: white;
  cursor: pointer;
  border-radius: 4px;
}

.refresh-btn:hover { background: #40a9ff; }

.x6-graph {
  width: 100%;
  height: 100%;
}

.legend {
  position: absolute;
  bottom: 20px;
  left: 20px;
  display: flex;
  gap: 20px;
  background: rgba(0, 0, 0, 0.03);
  padding: 10px 15px;
  border-radius: 4px;
  font-size: 12px;
}

.legend .item { display: flex; align-items: center; white-space: nowrap; }

.legend-symbol {
  width: 28px;
  height: 28px;
  margin-right: 7px;
  border: 2px solid;
  border-radius: 50%;
  background: #ffffff;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.legend-symbol img { width: 19px; height: 19px; }
.legend-symbol.manager { border-color: #1890ff; }
.legend-symbol.active { border-color: #52c41a; }
.legend-symbol.threat { border-color: #ff4d4f; }
.legend-symbol.offline { border-color: #555; }

.loading-mask {
  position: absolute;
  inset: 0;
  background: rgba(255,255,255,0.7);
  color: #374151;
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 20;
}
</style>
