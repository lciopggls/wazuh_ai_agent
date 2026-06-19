<script setup lang="ts">
import { ref, reactive, onMounted, onBeforeUnmount } from "vue";
import axios from 'axios';

// --- 1. 声明 Props：完美契合你给出的固定 attack_abstract 结构 ---
defineProps<{
  attackAbstract?: {
    hosts?: string[];          // 受影响的主机列表
    start_time?: string;       // 攻击开始时间
    end_time?: string;         // 攻击结束时间
    duration?: string;         // 攻击持续时间
    ioc_files?: string[];      // IOC 恶意文件
    ioc_domains?: string[];    // IOC 恶意域名
    ioc_processes?: string[];  // IOC 恶意进程
    tactics?: string[];        // 战术阶段/技术标签
    tactics_count?: number;    // 战术计数
  } | null;
}>();

// 环境变量获取
const indexerUser = import.meta.env.VITE_WAZUH_INDEXER_USER;
const indexerPass = import.meta.env.VITE_WAZUH_INDEXER_PASSWORD;
const INDEXER_AUTH = btoa(`${indexerUser}:${indexerPass}`);

const state = reactive({
  currentTab: 'alarm', 
  alarmData: [] as any[],
  loading: false,
  selectedTimeRange: '1h',
  detailVisible: false,
  selectedLog: null as any,
});

// 复制功能
const copyToClipboard = (text: string) => {
  navigator.clipboard.writeText(text).then(() => {
    alert("JSON 内容已复制");
  });
};

const formatDateTime = (timestamp: string) => {
  return new Date(timestamp).toLocaleString();
};

const getWazuhAlerts = async () => {
  state.loading = true;
  try {
    const timeMap: Record<string, string> = { '1h': 'now-1h', '1d': 'now-1d', '7d': 'now-7d' };
    const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 50,
      sort: [{ "timestamp": "desc" }],
      query: {
        bool: {
          must: [
            { range: { "rule.level": { "gte": 10 } } },
            { range: { "timestamp": { "gte": timeMap[state.selectedTimeRange] } } }
          ]
        }
      }
    }, {
      headers: { 
        'Authorization': `Basic ${INDEXER_AUTH}`,
        'Content-Type': 'application/json'
      }
    });

    state.alarmData = res.data.hits.hits.map((item: any) => ({
      ...item._source,
      formattedTime: formatDateTime(item._source.timestamp),
      raw: JSON.stringify(item._source, null, 2)
    }));
  } catch (err) {
    console.error("数据拉取失败", err);
  } finally {
    state.loading = false;
  }
};

const changeTimeRange = (range: string) => {
  state.selectedTimeRange = range;
  getWazuhAlerts();
};

const showDetail = (item: any) => {
  state.selectedLog = item;
  state.detailVisible = true;
};

let timer: any = null;
onMounted(() => {
  getWazuhAlerts();
  timer = setInterval(getWazuhAlerts, 20000);
});

onBeforeUnmount(() => {
  if (timer) clearInterval(timer);
});
</script>

<template>
  <div class="alert_container">
    <div class="toolbar flex">
      <div class="agent_tabs">
        <button 
          :class="['tab_item', state.currentTab === 'alarm' ? 'active' : '']"
          @click="state.currentTab = 'alarm'"
        >
          告警监控
        </button>
        <button 
          :class="['tab_item', state.currentTab === 'summary' ? 'active' : '']"
          @click="state.currentTab = 'summary'"
        >
          战术摘要
        </button>
      </div>

      <div v-if="state.currentTab === 'alarm'" class="filter_group">
        <button v-for="t in ['1h', '1d', '7d']" 
                :key="t" 
                :class="{ active: state.selectedTimeRange === t }"
                @click="changeTimeRange(t)">
          {{ t === '1h' ? '1小时' : t === '1d' ? '24小时' : '一周' }}
        </button>
      </div>
    </div>

    <template v-if="state.currentTab === 'alarm'">
      <div class="alert_header flex">
        <div class="header_item flex-15">时刻</div>
        <div class="header_item flex-05">级别</div>
        <div class="header_item flex-1">主机</div>
        <div class="header_item flex-2">描述</div>
      </div>
      
      <div class="scroll_wrapper" :class="{ 'manual_scroll': state.selectedTimeRange !== '1h' }">
        <div class="scroll_list" :class="{ 'animate_scroll': state.alarmData.length > 5 && state.selectedTimeRange === '1h' }">
          <div v-for="(item, index) in (state.selectedTimeRange === '1h' ? [...state.alarmData, ...state.alarmData] : state.alarmData)" 
               :key="index" 
               class="alert_item flex"
               @click="showDetail(item)">
            <div class="item_text time flex-15">{{ item.formattedTime }}</div>
            <div class="item_text level flex-05" :style="{ color: item.rule.level >= 13 ? '#f5023d' : '#e3b337' }">
              L{{ item.rule.level }}
            </div>
            <div class="item_text agent flex-1">{{ item.agent.name }}</div>
            <div class="item_text description flex-2">{{ item.rule.description }}</div>
          </div>
        </div>
      </div>
    </template>

    <template v-else-if="state.currentTab === 'summary'">
      <div class="summary_wrapper">
        <div v-if="attackAbstract" class="abstract_card_box">
          
          <div class="section_panel">
            <div class="panel_title">🖥️ 受影响主机资产 (Hosts)</div>
            <div class="panel_body">
              <div v-if="attackAbstract.hosts && attackAbstract.hosts.length > 0" class="host_list">
                <div v-for="(host, idx) in attackAbstract.hosts" :key="idx" class="host_item_badge">
                  {{ host }}
                </div>
              </div>
              <div v-else class="empty_text">暂无受影响主机数据</div>
            </div>
          </div>

          <div class="section_panel">
            <div class="panel_title">⏱️ 攻击事件计时与跨度</div>
            <div class="panel_body grid_2col">
              <div class="time_stat_box">
                <label>开始时间</label>
                <span>{{ attackAbstract.start_time || '--' }}</span>
              </div>
              <div class="time_stat_box">
                <label>结束时间</label>
                <span>{{ attackAbstract.end_time || '--' }}</span>
              </div>
              <div class="time_stat_box full_row">
                <label>持续时长</label>
                <span class="duration_highlight">⏳ {{ attackAbstract.duration || '0秒' }}</span>
              </div>
            </div>
          </div>

          <div class="section_panel">
            <div class="panel_title flex_between">
              <span>🎯 命中战术阶段 (Tactics)</span>
              <span class="count_tag">数量: {{ attackAbstract.tactics_count || 0 }}</span>
            </div>
            <div class="panel_body">
              <div v-if="attackAbstract.tactics && attackAbstract.tactics.length > 0" class="tag_cloud">
                <span v-for="(tactic, idx) in attackAbstract.tactics" :key="idx" class="tactic_tag">
                  {{ tactic }}
                </span>
              </div>
              <div v-else class="empty_text">未触发特定的战术标签匹配</div>
            </div>
          </div>

          <div class="section_panel">
            <div class="panel_title">🔍 关联 IOC 威胁情报特征</div>
            <div class="panel_body ioc_container">
              <div class="ioc_sub_block">
                <label>📁 恶意文件 (Files)</label>
                <div class="ioc_list">
                  <span v-for="(file, i) in attackAbstract.ioc_files" :key="i" class="ioc_badge">{{ file }}</span>
                  <span v-if="!attackAbstract.ioc_files?.length" class="ioc_none">无关联文件</span>
                </div>
              </div>
              <div class="ioc_sub_block">
                <label>⚙️ 恶意进程 (Processes)</label>
                <div class="ioc_list">
                  <span v-for="(proc, i) in attackAbstract.ioc_processes" :key="i" class="ioc_badge proc">{{ proc }}</span>
                  <span v-if="!attackAbstract.ioc_processes?.length" class="ioc_none">无关联进程</span>
                </div>
              </div>
              <div class="ioc_sub_block">
                <label>🌐 恶意域名 (Domains)</label>
                <div class="ioc_list">
                  <span v-for="(dom, i) in attackAbstract.ioc_domains" :key="i" class="ioc_badge domain">{{ dom }}</span>
                  <span v-if="!attackAbstract.ioc_domains?.length" class="ioc_none">无关联网络域名</span>
                </div>
              </div>
            </div>
          </div>

        </div>

        <div v-else class="abstract_empty">
          <div class="radar_loader"></div>
          <p>等待智能体生成战术简报数据...</p>
          <span>右侧 AI 窗口吐出溯源数据后，此处将自动解析并刷新大屏卡片。</span>
        </div>
      </div>
    </template>

    <teleport to="body">
      <div v-if="state.detailVisible" class="modal_overlay" @click.self="state.detailVisible = false">
        <div class="modal_content">
          <div class="modal_header">
            <h3>告警日志详情</h3>
            <div class="btns">
              <button class="copy_btn" @click="copyToClipboard(state.selectedLog.raw)">复制 JSON</button>
              <button class="close_btn" @click="state.detailVisible = false">关闭</button>
            </div>
          </div>
          <div class="log_view_container">
            <pre class="log_view">{{ state.selectedLog.raw }}</pre>
          </div>
        </div>
      </div>
    </teleport>
  </div>
</template>

<style scoped lang="scss">
/* 基础告警样式，与您原本保持 100% 一致 */
.alert_container {
  width: 100%; height: 100%; background: #ffffff; color: #374151; font-size: 12px; display: flex; flex-direction: column;
  
  .toolbar {
    padding: 10px; justify-content: space-between; background: rgba(0,0,0,0.03);
    
    .agent_tabs {
      display: flex; gap: 8px;
      .tab_item {
        background: transparent; padding: 4px 14px; font-size: 12px; color: #31ABE3; border: 1px solid #31ABE3; border-radius: 4px; cursor: pointer; transition: 0.2s;
        &:hover { background: rgba(49, 171, 227, 0.1); }
        &.active { background: #31ABE3; color: #fff; box-shadow: 0 0 10px rgba(49, 171, 227, 0.5); }
      }
    }
    .filter_group button {
      background: #f3f4f6; border: 1px solid #93c5fd; color: #1d4ed8; padding: 2px 8px; margin-left: 5px; cursor: pointer;
      &.active { background: #1d4ed8; color: #ffffff; }
    }
  }
  
  .flex { display: flex; align-items: center; }
  .flex_between { display: flex; justify-content: space-between; align-items: center; }
  .flex-05 { flex: 0.5; } .flex-1 { flex: 1; } .flex-15 { flex: 1.5; } .flex-2 { flex: 2; }

  .alert_header { background: rgba(29, 78, 216, 0.08); padding: 10px 0; color: #1d4ed8; font-weight: bold; .header_item { text-align: center; } }
  .scroll_wrapper { flex: 1; overflow: hidden; position: relative; &.manual_scroll { overflow-y: auto; .scroll_list { position: static; } } }
  .scroll_list { position: absolute; width: 100%; top: 0; }
  .animate_scroll { animation: scroll_up 30s linear infinite; &:hover { animation-play-state: paused; } }
  @keyframes scroll_up { 0% { transform: translateY(0); } 100% { transform: translateY(-50%); } }

  .alert_item {
    padding: 12px 0; border-bottom: 1px solid rgba(0, 0, 0, 0.06); cursor: pointer; transition: background 0.3s;
    &:hover { background: rgba(49, 171, 227, 0.05); }
    .item_text { text-align: center; padding: 0 5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  }

  // ⚡ 重构后的高科技固定字段看板面板样式
  .summary_wrapper {
    flex: 1;
    padding: 16px;
    background: #ffffff;
    overflow-y: auto;

    &::-webkit-scrollbar { width: 4px; }
    &::-webkit-scrollbar-thumb { background: #31ABE3; border-radius: 2px; }

    .abstract_card_box {
      display: flex;
      flex-direction: column;
      gap: 15px;
      animation: cardFadeIn 0.35s ease-out;

      .section_panel {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        overflow: hidden;

        .panel_title {
          background: #e0f2fe;
          padding: 8px 12px;
          color: #1d4ed8;
          font-weight: bold;
          font-size: 12px;
          border-bottom: 1px solid #e2e8f0;
          letter-spacing: 0.5px;

          .count_tag { font-size: 11px; background: #1d4ed8; color: #ffffff; padding: 1px 6px; border-radius: 10px; }
        }

        .panel_body {
          padding: 12px;

          .empty_text { color: rgba(0, 0, 0, 0.35); font-style: italic; text-align: center; padding: 5px 0; }
          
          // 主机列表呈现
          .host_list {
            display: flex; flex-direction: column; gap: 6px;
            .host_item_badge {
              background: #f0f7ff; border: 1px dashed #93c5fd;
              padding: 8px 12px; color: #374151; font-family: monospace; border-radius: 4px; font-size: 12px;
            }
          }

          // 2列网格布局
          &.grid_2col {
            display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
            .full_row { grid-column: span 2; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 8px; }
          }

          .time_stat_box {
            display: flex; flex-direction: column; gap: 4px;
            label { font-size: 10px; color: rgba(29, 78, 216, 0.7); }
            span { font-size: 12px; color: #374151; font-family: monospace; }
            .duration_highlight { color: #ffeb3b; font-weight: bold; font-size: 13px; }
          }

          // 战术标签云
          .tag_cloud {
            display: flex; flex-wrap: wrap; gap: 6px;
            .tactic_tag {
              background: rgba(244, 67, 54, 0.15); border: 1px solid rgba(244, 67, 54, 0.4);
              color: #ff8a80; padding: 3px 8px; border-radius: 4px; font-weight: bold;
            }
          }

          // IOC特征块
          &.ioc_container { display: flex; flex-direction: column; gap: 10px; }
          .ioc_sub_block {
            label { font-size: 11px; color: #1d4ed8; display: block; margin-bottom: 5px; font-weight: bold; }
            .ioc_list { display: flex; flex-wrap: wrap; gap: 5px; }
            .ioc_badge {
              font-family: monospace; font-size: 11px; background: rgba(0,0,0,0.03);
              border: 1px solid rgba(0,0,0,0.1); padding: 2px 6px; border-radius: 3px; color: #374151;
              &.proc { color: #ffb74d; background: rgba(255,183,77,0.05); border-color: rgba(255,183,77,0.3); }
              &.domain { color: #4fc3f7; background: rgba(79,195,247,0.05); border-color: rgba(79,195,247,0.3); }
            }
            .ioc_none { font-size: 11px; color: rgba(0,0,0,0.2); }
          }
        }
      }
    }

    .abstract_empty {
      display: flex; flex-direction: column; align-items: center; justify-content: center; padding-top: 100px; text-align: center;
      .radar_loader { width: 32px; height: 32px; border: 3px solid rgba(49, 171, 227, 0.1); border-top-color: #00fdfa; border-radius: 50%; animation: spin 1s linear infinite; margin-bottom: 16px; }
      p { font-size: 13px; color: #1d4ed8; margin: 0 0 6px 0; font-weight: bold; }
      span { font-size: 11px; color: rgba(0, 0, 0, 0.35); max-width: 250px; line-height: 1.5; }
    }
  }
}

@keyframes cardFadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
@keyframes spin { to { transform: rotate(360deg); } }

/* 弹窗样式 */
.modal_overlay { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(255, 255, 255, 0.9); display: flex; justify-content: center; align-items: center; z-index: 9999; }
.modal_content {
  background: #ffffff; width: 75%; max-height: 85vh; border: 1px solid #93c5fd; box-shadow: 0 0 20px rgba(0,0,0,0.1); padding: 20px; display: flex; flex-direction: column; box-sizing: border-box;
  .modal_header {
    display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; border-bottom: 1px solid #e5e7eb; padding-bottom: 10px;
    h3 { margin: 0; color: #1d4ed8; font-size: 16px; }
    button {
      border: none; color: white; padding: 6px 12px; margin-left: 10px; cursor: pointer; font-weight: bold; border-radius: 4px; transition: 0.2s;
      &.copy_btn { background: #f3f4f6; border: 1px solid #93c5fd; color: #1d4ed8; &:hover { background: rgba(29,78,216,0.1); } }
      &.close_btn { background: #31ABE3; &:hover { background: #00fdfa; color: #000; } }
    }
  }
  .log_view_container { flex: 1; min-height: 0; overflow: auto; background: #f3f4f6; border-radius: 4px; padding: 10px; }
  .log_view { margin: 0; color: #374151; font-family: 'Courier New', monospace; font-size: 13px; white-space: pre-wrap; word-break: break-all; }
}
</style>