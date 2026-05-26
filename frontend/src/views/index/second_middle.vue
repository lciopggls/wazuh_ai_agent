<script setup lang="ts">
import { ref, watch, onUnmounted } from 'vue';

const props = defineProps<{
  allSessions: Record<string, any[]>;
  agentId: string;
}>();

const emit = defineEmits(['clear-sessions']);

const resourceLinks = ref<any[]>([]);
const activeUrls = new Set<string>();
const timeCache = new Map<string, string>();
const lastTotalMessages = ref(0);

// 清理所有 URL 内存
const cleanupUrls = () => {
  activeUrls.forEach(url => URL.revokeObjectURL(url));
  activeUrls.clear();
};

const handleClearAll = () => {
  cleanupUrls();
  resourceLinks.value = [];
  timeCache.clear();
  lastTotalMessages.value = 0;
  emit('clear-sessions', props.agentId);
};

watch(() => props.allSessions, (newSessions) => {
  if (!newSessions) return;

  // 1. 筛选出当前智能体相关的会话
  const relevantEntries = Object.entries(newSessions)
    .filter(([key]) => key.startsWith(props.agentId));

  // 2. 计算消息总数用于判断是否需要更新解析
  const currentTotalMessages = relevantEntries.reduce((sum, [_, msgs]) => sum + msgs.length, 0);

  // 如果消息总数没变且列表已有内容，跳过（性能优化）
  if (currentTotalMessages === lastTotalMessages.value && resourceLinks.value.length > 0) {
    return;
  }

  const newResourceLinks: any[] = [];
  const validSessionIds = new Set();

  relevantEntries.forEach(([sessionId, messages]) => {
    // 逆序查找最新的可视化节点
    const svgMsg = [...messages].reverse().find(m => 
      m.node === 'Visualization_Node' && 
      m.content?.includes('</svg>')
    );

    if (svgMsg) {
      const match = svgMsg.content.match(/<svg[\s\S]*?<\/svg>/);
      if (match) {
        validSessionIds.add(sessionId);
        
        // 查找是否已有该会话的 URL，避免重复创建
        const existing = resourceLinks.value.find(l => l.id === sessionId);
        let url = '';

        if (existing) {
          url = existing.url;
        } else {
          const blob = new Blob([match[0]], { type: 'image/svg+xml' });
          url = URL.createObjectURL(blob);
          activeUrls.add(url);
        }

        if (!timeCache.has(sessionId)) {
          timeCache.set(sessionId, new Date().toLocaleTimeString());
        }

        newResourceLinks.push({
          id: sessionId, 
          name: `分析图谱 (${sessionId.split('_').pop()})`,
          url: url,
          time: timeCache.get(sessionId)
        });
      }
    }
  });

  // 精确清理：销毁那些已经不在会话列表中的 URL
  activeUrls.forEach(url => {
    if (!newResourceLinks.some(link => link.url === url)) {
      URL.revokeObjectURL(url);
      activeUrls.delete(url);
    }
  });

  resourceLinks.value = newResourceLinks;
  lastTotalMessages.value = currentTotalMessages;
}, { deep: true, immediate: true });

onUnmounted(() => {
  cleanupUrls();
});
</script>

<template>
  <div class="resource-container">
    <div class="header">
      <span class="title">分析资源列表</span>
      <button v-if="resourceLinks.length > 0" class="clear-btn" @click="handleClearAll">清空列表</button>
    </div>

    <div v-if="resourceLinks.length === 0" class="empty-state">
      等待安全分析完成，资源将在此生成...
    </div>

    <div v-else class="link-list">
      <div v-for="link in resourceLinks" :key="link.id" class="link-item">
        <div class="file-icon">📊</div>
        <div class="file-info">
          <div class="file-name">{{ link.name }}</div>
          <div class="file-time">生成时间：{{ link.time }}</div>
        </div>
        <a :href="link.url" target="_blank" class="action-link">查看视图</a>
      </div>
    </div>
  </div>
</template>

<style scoped lang="scss">
.resource-container {
  height: 100%;
  padding: 10px;
  display: flex;
  flex-direction: column;

  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
    padding-bottom: 8px;
    border-bottom: 1px solid rgba(49, 171, 227, 0.2);

    .title {
      color: #00fdfa;
      font-size: 14px;
      font-weight: bold;
    }

    .clear-btn {
      background: transparent;
      border: 1px solid rgba(255, 71, 71, 0.5);
      color: #ff4747;
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 4px;
      cursor: pointer;
      transition: 0.2s;

      &:hover {
        background: #ff4747;
        color: #fff;
      }
    }
  }

  .empty-state {
    color: rgba(255,255,255,0.2);
    text-align: center;
    margin-top: 40px;
    font-size: 13px;
    flex: 1;
  }

  .link-list {
    flex: 1;
    overflow-y: auto;

    .link-item {
      display: flex;
      align-items: center;
      background: rgba(49, 171, 227, 0.08);
      border: 1px solid rgba(49, 171, 227, 0.2);
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 12px;
      transition: 0.3s;

      &:hover {
        background: rgba(49, 171, 227, 0.15);
        border-color: #00fdfa;
      }

      .file-icon { font-size: 20px; margin-right: 12px; }
      .file-info {
        flex: 1;
        .file-name { color: #fff; font-size: 13px; font-weight: bold; }
        .file-time { color: #666; font-size: 11px; margin-top: 2px; }
      }

      .action-link {
        color: #00fdfa;
        font-size: 12px;
        text-decoration: none;
        padding: 4px 10px;
        border: 1px solid #00fdfa;
        border-radius: 4px;
        &:hover { background: #00fdfa; color: #000; }
      }
    }
  }
}
</style>