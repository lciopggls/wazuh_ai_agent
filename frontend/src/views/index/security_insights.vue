<template>
  <div class="security-dashboard">
    <!-- 顶部标题 -->
    <div class="dashboard-header">
      <h2>🔐 安全监控中心</h2>
      <div class="header-actions">
        <el-button size="small" type="primary" @click="refreshAllData" :loading="globalLoading">
          ⟳ 刷新数据
        </el-button>
        <el-tag type="info">数据实时更新</el-tag>
      </div>
    </div>

    <!-- 仪表板内容 -->
    <div v-loading="dashboardLoading" class="dashboard-content">
      <!-- 统计卡片 -->
      <el-row :gutter="20" class="stats-row">
        <el-col :xs="12" :sm="6" v-for="stat in statsCards" :key="stat.label">
          <div class="stat-card" :class="stat.className">
            <div class="stat-number">{{ stat.value }}</div>
            <div class="stat-label">{{ stat.label }}</div>
            <div class="stat-icon">{{ stat.icon }}</div>
          </div>
        </el-col>
      </el-row>

      <!-- 图表区域 -->
      <el-row :gutter="20" class="charts-row">
        <el-col :xs="24" :lg="12">
          <el-card class="chart-card" shadow="hover">
            <template #header>
              <div class="card-header">
                <span>📈 Top 10 告警等级演变 (每30分钟)</span>
                <el-tag size="small" type="info">最近24小时</el-tag>
              </div>
            </template>
            <div id="alertLevelChart" class="chart-container"></div>
          </el-card>
        </el-col>
        <el-col :xs="24" :lg="12">
          <el-card class="chart-card" shadow="hover">
            <template #header>
              <div class="card-header">
                <span>🎯 Top 10 MITRE ATT&CKs (每30分钟)</span>
                <el-tag size="small" type="info">最近24小时</el-tag>
              </div>
            </template>
            <div id="mitreChart" class="chart-container"></div>
          </el-card>
        </el-col>
      </el-row>

      <el-row :gutter="20" class="charts-row">
        <el-col :xs="24" :lg="12">
          <el-card class="chart-card" shadow="hover">
            <template #header>
              <div class="card-header">
                <span>🖥️ Top 5 Agents</span>
                <el-tag size="small" type="info">告警数量</el-tag>
              </div>
            </template>
            <div id="topAgentsChart" class="chart-container"></div>
          </el-card>
        </el-col>
        <el-col :xs="24" :lg="12">
          <el-card class="chart-card" shadow="hover">
            <template #header>
              <div class="card-header">
                <span>📉 告警演变 - Top 5 Agents</span>
                <el-tag size="small" type="info">每12小时</el-tag>
              </div>
            </template>
            <div id="agentTrendChart" class="chart-container"></div>
          </el-card>
        </el-col>
      </el-row>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onBeforeUnmount, nextTick } from "vue";
import { ElMessage } from "element-plus";
import axios from 'axios';
import * as echarts from 'echarts';

// ─────────────────────────────────────────────
// 1. 环境配置与认证
// ─────────────────────────────────────────────
const indexerUser = import.meta.env.VITE_WAZUH_INDEXER_USER;
const indexerPass = import.meta.env.VITE_WAZUH_INDEXER_PASSWORD;
const INDEXER_AUTH = btoa(`${indexerUser}:${indexerPass}`);

// ─────────────────────────────────────────────
// 2. 仪表板模块
// ─────────────────────────────────────────────
const globalLoading = ref(false);
const dashboardLoading = ref(false);

const dashboardStats = reactive({
  total: 0,
  level12Above: 0,
  authFailure: 0,
  authSuccess: 0,
  alertLevelData: { timestamps: [] as string[], series: [] as any[] },
  mitreData: { timestamps: [] as string[], series: [] as any[] },
  topAgents: [] as any[],
  agentTrendData: { timestamps: [] as string[], series: [] as any[] }
});

// 统计卡片数据
const statsCards = computed(() => [
  {
    label: '总告警',
    value: dashboardStats.total.toLocaleString(),
    className: 'total',
    icon: '📊'
  },
  {
    label: '≥12级告警',
    value: dashboardStats.level12Above.toLocaleString(),
    className: 'critical',
    icon: '🔴'
  },
  {
    label: '认证失败',
    value: dashboardStats.authFailure.toLocaleString(),
    className: 'warning',
    icon: '⚠️'
  },
  {
    label: '认证成功',
    value: dashboardStats.authSuccess.toLocaleString(),
    className: 'success',
    icon: '✅'
  }
]);

// 图表实例
let alertLevelChartInstance: echarts.ECharts | null = null;
let mitreChartInstance: echarts.ECharts | null = null;
let topAgentsChartInstance: echarts.ECharts | null = null;
let agentTrendChartInstance: echarts.ECharts | null = null;

// 获取告警等级演变数据
const fetchAlertLevelTrend = async () => {
  try {
    const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 0,
      query: {
        range: {
          timestamp: { gte: 'now-24h' }
        }
      },
      aggs: {
        alerts_over_time: {
          date_histogram: {
            field: 'timestamp',
            fixed_interval: '30m'
          },
          aggs: {
            by_level: {
              terms: {
                field: 'rule.level',
                size: 10,
                order: { '_count': 'desc' }
              }
            }
          }
        }
      }
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}`, 'Content-Type': 'application/json' }
    });

    const buckets = res.data.aggregations.alerts_over_time.buckets;
    dashboardStats.alertLevelData.timestamps = buckets.map((b: any) =>
      new Date(b.key).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
    );

    // 构建等级数据
    const levelMap = new Map();
    buckets.forEach((bucket: any) => {
      bucket.by_level.buckets.forEach((level: any) => {
        if (!levelMap.has(level.key)) {
          levelMap.set(level.key, new Array(buckets.length).fill(0));
        }
        const data = levelMap.get(level.key);
        const index = buckets.indexOf(bucket);
        data[index] = level.doc_count;
      });
    });

    dashboardStats.alertLevelData.series = Array.from(levelMap.entries())
      .sort((a, b) => b[1].reduce((s: number, v: number) => s + v, 0) - a[1].reduce((s: number, v: number) => s + v, 0))
      .slice(0, 10)
      .map(([level, data]) => ({
        name: `Level ${level}`,
        type: 'line',
        stack: 'total',
        data: data,
        smooth: true
      }));

  } catch (err) {
    console.error("告警等级趋势获取失败", err);
  }
};

// 获取MITRE ATT&CK数据
const fetchMitreData = async () => {
  try {
    const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 0,
      query: {
        range: {
          timestamp: { gte: 'now-24h' }
        }
      },
      aggs: {
        mitre_techniques: {
          terms: {
            field: 'rule.mitre.id',
            size: 10
          },
          aggs: {
            over_time: {
              date_histogram: {
                field: 'timestamp',
                fixed_interval: '30m'
              }
            }
          }
        }
      }
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}`, 'Content-Type': 'application/json' }
    });

    const buckets = res.data.aggregations.mitre_techniques.buckets;
    dashboardStats.mitreData.series = buckets.map((b: any) => ({
      name: b.key || 'Unknown',
      value: b.doc_count
    }));

    if (buckets.length > 0 && buckets[0].over_time?.buckets) {
      dashboardStats.mitreData.timestamps = buckets[0].over_time.buckets.map((b: any) =>
        new Date(b.key).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
      );
    }

  } catch (err) {
    console.error("MITRE数据获取失败", err);
  }
};

// 获取Top Agents
const fetchTopAgents = async () => {
  try {
    const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 0,
      query: {
        range: {
          timestamp: { gte: 'now-24h' }
        }
      },
      aggs: {
        top_agents: {
          terms: {
            field: 'agent.name',
            size: 5
          }
        }
      }
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}`, 'Content-Type': 'application/json' }
    });

    dashboardStats.topAgents = res.data.aggregations.top_agents.buckets.map((b: any) => ({
      name: b.key || 'Unknown',
      count: b.doc_count
    }));

  } catch (err) {
    console.error("Top Agents获取失败", err);
  }
};

// 获取Agent趋势
const fetchAgentTrend = async () => {
  try {
    const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 0,
      query: {
        range: {
          timestamp: { gte: 'now-12h' }
        }
      },
      aggs: {
        top_agents: {
          terms: {
            field: 'agent.name',
            size: 5
          },
          aggs: {
            over_time: {
              date_histogram: {
                field: 'timestamp',
                fixed_interval: '30m'
              }
            }
          }
        }
      }
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}`, 'Content-Type': 'application/json' }
    });

    const agentBuckets = res.data.aggregations.top_agents.buckets;
    if (agentBuckets.length > 0) {
      const timestamps = agentBuckets[0].over_time.buckets.map((b: any) =>
        new Date(b.key).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
      );
      dashboardStats.agentTrendData.timestamps = timestamps;

      dashboardStats.agentTrendData.series = agentBuckets.map((agent: any) => ({
        name: agent.key || 'Unknown',
        type: 'line',
        data: agent.over_time.buckets.map((b: any) => b.doc_count),
        smooth: true
      }));
    }

  } catch (err) {
    console.error("Agent趋势获取失败", err);
  }
};

// 渲染所有图表
const renderAllCharts = () => {
  renderAlertLevelChart();
  renderMitreChart();
  renderTopAgentsChart();
  renderAgentTrendChart();
};

// 渲染告警等级图表
const renderAlertLevelChart = () => {
  const chartDom = document.getElementById('alertLevelChart');
  if (!chartDom) return;

  if (!alertLevelChartInstance) {
    alertLevelChartInstance = echarts.init(chartDom);
  }

  const option = {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' }
    },
    legend: {
      data: dashboardStats.alertLevelData.series.map(s => s.name),
      textStyle: { color: '#666' },
      right: 10,
      top: 0,
      itemWidth: 12,
      itemHeight: 8
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      data: dashboardStats.alertLevelData.timestamps,
      axisLabel: { color: '#666', fontSize: 11 },
      axisLine: { lineStyle: { color: '#e0e0e0' } }
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: '#666' },
      splitLine: { lineStyle: { color: '#f0f0f0' } }
    },
    series: dashboardStats.alertLevelData.series.map((s, index) => ({
      ...s,
      areaStyle: { opacity: 0.3 },
      lineStyle: { width: 2 },
      itemStyle: {
        color: ['#31ABE3', '#f5023d', '#e3b337', '#6c7a89', '#ff8c00', '#00d4ff', '#ff6b6b', '#ffd93d', '#6bcb77', '#4d96ff'][index % 10]
      }
    }))
  };

  alertLevelChartInstance.setOption(option, true);
  alertLevelChartInstance.resize();
};

// 渲染MITRE图表
const renderMitreChart = () => {
  const chartDom = document.getElementById('mitreChart');
  if (!chartDom) return;

  if (!mitreChartInstance) {
    mitreChartInstance = echarts.init(chartDom);
  }

  const option = {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' }
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      data: dashboardStats.mitreData.series.map((s: any) => s.name),
      axisLabel: { color: '#666', fontSize: 10, rotate: 15 },
      axisLine: { lineStyle: { color: '#e0e0e0' } }
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: '#666' },
      splitLine: { lineStyle: { color: '#f0f0f0' } }
    },
    series: [{
      type: 'bar',
      data: dashboardStats.mitreData.series.map((s: any) => s.value),
      itemStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: '#ff6b6b' },
          { offset: 1, color: '#ffd93d' }
        ])
      },
      barWidth: '50%'
    }]
  };

  mitreChartInstance.setOption(option, true);
  mitreChartInstance.resize();
};

// 渲染Top Agents图表
const renderTopAgentsChart = () => {
  const chartDom = document.getElementById('topAgentsChart');
  if (!chartDom) return;

  if (!topAgentsChartInstance) {
    topAgentsChartInstance = echarts.init(chartDom);
  }

  const option = {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' }
    },
    grid: {
      left: '15%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'value',
      axisLabel: { color: '#666' },
      splitLine: { lineStyle: { color: '#f0f0f0' } }
    },
    yAxis: {
      type: 'category',
      data: dashboardStats.topAgents.map((a: any) => a.name),
      axisLabel: { color: '#666', fontSize: 12 },
      axisLine: { lineStyle: { color: '#e0e0e0' } }
    },
    series: [{
      type: 'bar',
      data: dashboardStats.topAgents.map((a: any) => a.count),
      itemStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
          { offset: 0, color: '#31ABE3' },
          { offset: 1, color: '#2378A3' }
        ])
      },
      barWidth: '60%',
      label: {
        show: true,
        position: 'right',
        color: '#666'
      }
    }]
  };

  topAgentsChartInstance.setOption(option, true);
  topAgentsChartInstance.resize();
};

// 渲染Agent趋势图表
const renderAgentTrendChart = () => {
  const chartDom = document.getElementById('agentTrendChart');
  if (!chartDom) return;

  if (!agentTrendChartInstance) {
    agentTrendChartInstance = echarts.init(chartDom);
  }

  const colors = ['#31ABE3', '#f5023d', '#e3b337', '#6c7a89', '#ff8c00'];

  const option = {
    tooltip: {
      trigger: 'axis'
    },
    legend: {
      data: dashboardStats.agentTrendData.series.map((s: any) => s.name),
      textStyle: { color: '#666' },
      right: 10,
      top: 0,
      itemWidth: 12,
      itemHeight: 8
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      data: dashboardStats.agentTrendData.timestamps,
      axisLabel: { color: '#666', fontSize: 11 },
      axisLine: { lineStyle: { color: '#e0e0e0' } }
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: '#666' },
      splitLine: { lineStyle: { color: '#f0f0f0' } }
    },
    series: dashboardStats.agentTrendData.series.map((s: any, index: number) => ({
      ...s,
      lineStyle: { width: 2 },
      itemStyle: { color: colors[index % colors.length] },
      areaStyle: { opacity: 0.2 }
    }))
  };

  agentTrendChartInstance.setOption(option, true);
  agentTrendChartInstance.resize();
};

// 获取仪表板数据
const getDashboardStats = async () => {
  dashboardLoading.value = true;
  try {
    const totalRes = await axios.post('/wazuh-indexer/wazuh-alerts-*/_count', {
      query: { match_all: {} }
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}`, 'Content-Type': 'application/json' }
    });
    dashboardStats.total = totalRes.data.count;

    const level12Res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_count', {
      query: {
        range: { 'rule.level': { gte: 12 } }
      }
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}`, 'Content-Type': 'application/json' }
    });
    dashboardStats.level12Above = level12Res.data.count;

    const authFailRes = await axios.post('/wazuh-indexer/wazuh-alerts-*/_count', {
      query: {
        term: { 'data.authFail': true }
      }
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}`, 'Content-Type': 'application/json' }
    });
    dashboardStats.authFailure = authFailRes.data.count;

    const authSuccessRes = await axios.post('/wazuh-indexer/wazuh-alerts-*/_count', {
      query: {
        bool: {
          must: [
            { exists: { field: 'data.authFail' } },
            { term: { 'data.authFail': false } }
          ]
        }
      }
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}`, 'Content-Type': 'application/json' }
    });
    dashboardStats.authSuccess = authSuccessRes.data.count;

    await fetchAlertLevelTrend();
    await fetchMitreData();
    await fetchTopAgents();
    await fetchAgentTrend();

    await nextTick();
    renderAllCharts();

  } catch (err) {
    console.error("仪表板数据获取失败", err);
    ElMessage.error("仪表板数据加载失败");
  } finally {
    dashboardLoading.value = false;
  }
};

// 刷新所有数据
const refreshAllData = async () => {
  globalLoading.value = true;
  try {
    await getDashboardStats();
    ElMessage.success('数据已刷新');
  } catch (error) {
    ElMessage.error('刷新失败');
  } finally {
    globalLoading.value = false;
  }
};

// 窗口resize处理
const handleResize = () => {
  alertLevelChartInstance?.resize();
  mitreChartInstance?.resize();
  topAgentsChartInstance?.resize();
  agentTrendChartInstance?.resize();
};

// ─────────────────────────────────────────────
// 生命周期（合并为单一挂载/卸载钩子）
// ─────────────────────────────────────────────
let refreshInterval: number | null = null;

onMounted(async () => {
  await getDashboardStats();
  window.addEventListener('resize', handleResize);

  // 自动刷新（每30秒）
  refreshInterval = window.setInterval(() => {
    getDashboardStats();
  }, 30000);
});

onBeforeUnmount(() => {
  window.removeEventListener('resize', handleResize);

  alertLevelChartInstance?.dispose();
  mitreChartInstance?.dispose();
  topAgentsChartInstance?.dispose();
  agentTrendChartInstance?.dispose();

  if (refreshInterval) {
    clearInterval(refreshInterval);
  }
});
</script>

<style scoped>
.security-dashboard {
  padding: 20px;
  background: transparent;
  height: 100%;
  overflow-y: auto;
  color: #333;
}

.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 0 20px 0;
  border-bottom: 1px solid #e5e7eb;
  margin-bottom: 20px;
  flex-wrap: wrap;
  gap: 10px;
}

.dashboard-header h2 {
  margin: 0;
  color: #1f2937;
  font-weight: 600;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 15px;
  flex-wrap: wrap;
}

/* 统计卡片 */
.stats-row {
  margin-bottom: 20px;
}

.stat-card {
  background: #fff;
  border-radius: 12px;
  padding: 20px;
  text-align: center;
  border: 1px solid #e5e7eb;
  position: relative;
  overflow: hidden;
  transition: all 0.3s ease;
  min-height: 100px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}

.stat-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 8px 25px rgba(49, 171, 227, 0.12);
  border-color: #31ABE3;
}

.stat-card .stat-number {
  font-size: 36px;
  font-weight: bold;
  color: #1f2937;
  line-height: 1.2;
}

.stat-card .stat-label {
  font-size: 14px;
  color: #6b7280;
  margin-top: 8px;
}

.stat-card .stat-icon {
  font-size: 28px;
  position: absolute;
  right: 15px;
  top: 15px;
  opacity: 0.15;
}

.stat-card.total .stat-number { color: #31ABE3; }
.stat-card.critical .stat-number { color: #dc2626; }
.stat-card.warning .stat-number { color: #d97706; }
.stat-card.success .stat-number { color: #16a34a; }

.stat-card.total { border-left: 4px solid #31ABE3; }
.stat-card.critical { border-left: 4px solid #dc2626; }
.stat-card.warning { border-left: 4px solid #d97706; }
.stat-card.success { border-left: 4px solid #16a34a; }

/* 图表卡片 */
.charts-row {
  margin-bottom: 20px;
}

.chart-card {
  background: #fff;
  border: 1px solid #e5e7eb;
  border-radius: 12px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}

.chart-card :deep(.el-card__header) {
  border-bottom: 1px solid #e5e7eb;
  padding: 15px 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: #374151;
  font-weight: 600;
}

.chart-container {
  height: 320px;
  width: 100%;
}

/* 滚动条美化 */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

::-webkit-scrollbar-track {
  background: #f1f5f9;
}

::-webkit-scrollbar-thumb {
  background: #cbd5e1;
  border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
  background: #94a3b8;
}

/* 响应式 */
@media (max-width: 768px) {
  .security-dashboard {
    padding: 10px;
  }

  .stat-card .stat-number {
    font-size: 24px;
  }

  .chart-container {
    height: 250px;
  }

  .dashboard-header h2 {
    font-size: 18px;
  }

  .stat-card .stat-icon {
    display: none;
  }
}
</style>
