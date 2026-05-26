<script setup lang="ts">
import { ref, reactive, onMounted, onBeforeUnmount } from "vue";
import axios from 'axios';

// 环境变量获取
const indexerUser = import.meta.env.VITE_WAZUH_INDEXER_USER;
const indexerPass = import.meta.env.VITE_WAZUH_INDEXER_PASSWORD;
const INDEXER_AUTH = btoa(`${indexerUser}:${indexerPass}`);

const state = reactive({
  currentTab: 'alarm', // 新增：用于控制“告警监控”和“摘要”按钮的切换状态
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
    <!-- 头部工具栏 -->
    <div class="toolbar flex">
      <!-- 修改点：将标题改为可点击的按钮组 -->
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
          摘要
        </button>
      </div>

      <!-- 时间筛选过滤组 -->
      <div class="filter_group">
        <button v-for="t in ['1h', '1d', '7d']" 
                :key="t" 
                :class="{ active: state.selectedTimeRange === t }"
                @click="changeTimeRange(t)">
          {{ t === '1h' ? '1小时' : t === '1d' ? '24小时' : '一周' }}
        </button>
      </div>
    </div>

    <!-- 告警内容区域 (当选中“告警监控”时展示) -->
    <template v-if="state.currentTab === 'alarm'">
      <!-- 表头 -->
      <div class="alert_header flex">
        <div class="header_item flex-15">时刻</div>
        <div class="header_item flex-05">级别</div>
        <div class="header_item flex-1">主机</div>
        <div class="header_item flex-2">描述</div>
      </div>
      
      <!-- 列表容器 -->
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

    <!-- 摘要内容区域 (当选中“摘要”时展示，此处可以根据实际需求替换内容) -->
    <template v-else-if="state.currentTab === 'summary'">
      <div class="summary_wrapper">
        <p>这里是摘要信息视图，可以根据后续接口加入统计或AI摘要数据。</p>
      </div>
    </template>

    <!-- 详情弹窗 -->
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
.alert_container {
  width: 100%; height: 100%; background: #0a1118; color: #fff; font-size: 12px; display: flex; flex-direction: column;
  
  .toolbar {
    padding: 10px; justify-content: space-between; background: rgba(255,255,255,0.05);
    
    // 新增：按钮标签组样式（完美复刻第二个组件的科技蓝风格）
    .agent_tabs {
      display: flex;
      gap: 8px;
      .tab_item {
        background: transparent;
        padding: 4px 14px;
        font-size: 12px;
        color: #31ABE3;
        border: 1px solid #31ABE3;
        border-radius: 4px;
        cursor: pointer;
        transition: 0.2s;
        &:hover { background: rgba(49, 171, 227, 0.1); }
        &.active { background: #31ABE3; color: #fff; box-shadow: 0 0 10px rgba(49, 171, 227, 0.5); }
      }
    }

    .filter_group button {
      background: #1a2635; border: 1px solid #31ABE3; color: #31ABE3; padding: 2px 8px; margin-left: 5px; cursor: pointer;
      &.active { background: #31ABE3; color: #fff; }
    }
  }
  
  .flex { display: flex; align-items: center; }
  .flex-05 { flex: 0.5; } .flex-1 { flex: 1; } .flex-15 { flex: 1.5; } .flex-2 { flex: 2; }

  .alert_header { background: rgba(49, 171, 227, 0.2); padding: 10px 0; color: #31ABE3; font-weight: bold; .header_item { text-align: center; } }
  
  .scroll_wrapper {
    flex: 1; overflow: hidden; position: relative;
    &.manual_scroll { overflow-y: auto; .scroll_list { position: static; } }
  }
  .scroll_list { position: absolute; width: 100%; top: 0; }
  .animate_scroll { animation: scroll_up 30s linear infinite; &:hover { animation-play-state: paused; } }
  @keyframes scroll_up { 0% { transform: translateY(0); } 100% { transform: translateY(-50%); } }

  .alert_item {
    padding: 12px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.05); cursor: pointer; transition: background 0.3s;
    &:hover { background: rgba(49, 171, 227, 0.1); }
    .item_text { text-align: center; padding: 0 5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  }

  // 新增：摘要内容容器的基本样式
  .summary_wrapper {
    padding: 20px;
    color: #a5d6ff;
    font-size: 13px;
  }
}

/* 弹窗样式保持原样 */
.modal_overlay {
  position: fixed;
  top: 0; left: 0;
  width: 100vw; height: 100vh;
  background: rgba(0, 0, 0, 0.85);
  display: flex; justify-content: center; align-items: center;
  z-index: 9999;
}

.modal_content {
  background: #1a2635;
  width: 75%;
  max-height: 85vh;
  border: 1px solid #31ABE3;
  box-shadow: 0 0 20px rgba(49, 171, 227, 0.3);
  padding: 20px;
  display: flex;
  flex-direction: column;
  box-sizing: border-box;

  .modal_header {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 15px; border-bottom: 1px solid rgba(49, 171, 227, 0.3);
    padding-bottom: 10px;
    h3 { margin: 0; color: #31ABE3; font-size: 16px; }
    
    button {
      border: none; color: white; padding: 6px 12px; margin-left: 10px; 
      cursor: pointer; font-weight: bold; border-radius: 4px; transition: 0.2s;
      &.copy_btn { background: #1a2635; border: 1px solid #31ABE3; color: #31ABE3; &:hover { background: rgba(49,171,227,0.1); } }
      &.close_btn { background: #31ABE3; &:hover { background: #00fdfa; color: #000; } }
    }
  }

  .log_view_container {
    flex: 1;
    min-height: 0;
    overflow: auto;
    background: #0d1117;
    border-radius: 4px;
    padding: 10px;
  }

  .log_view {
    margin: 0;
    color: #a5d6ff;
    font-family: 'Courier New', monospace;
    font-size: 13px;
    white-space: pre-wrap; 
    word-break: break-all;
  }
}
</style>