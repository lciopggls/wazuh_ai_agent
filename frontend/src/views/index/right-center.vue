<script setup lang="ts">
import { ref, onMounted, computed } from "vue";
import axios from 'axios';

const indexerUser = import.meta.env.VITE_WAZUH_INDEXER_USER;
const indexerPass = import.meta.env.VITE_WAZUH_INDEXER_PASSWORD;
const INDEXER_AUTH = btoa(`${indexerUser}:${indexerPass}`);

// ── 高频告警状态 ──
interface TopAlert {
  label: string;
  count: number;
  level: number;
  ruleId: number;
}
const topAlerts = ref<TopAlert[]>([]);
const topLoading = ref(false);

// ── 获取高频告警（客户端分组，避免 API 500） ──
const fetchTopAlerts = async () => {
  topLoading.value = true;
  try {
    const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 500,
      sort: [{ "timestamp": "desc" }],
      query: {
        range: { timestamp: { gte: 'now-24h' } }
      },
      _source: ['rule.description', 'rule.level', 'rule.id']
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}`, 'Content-Type': 'application/json' }
    });

    const hits: any[] = res.data.hits?.hits || [];

    // 客户端分组：按 rule.description 聚合
    const groups = new Map<string, { count: number; maxLevel: number; ruleId: number }>();

    for (const hit of hits) {
      const src = hit._source;
      const desc = src.rule?.description || '未知告警';
      const level = src.rule?.level || 0;
      const id = src.rule?.id || 0;

      const existing = groups.get(desc);
      if (existing) {
        existing.count++;
        if (level > existing.maxLevel) existing.maxLevel = level;
      } else {
        groups.set(desc, { count: 1, maxLevel: level, ruleId: id });
      }
    }

    // 过滤 ≥7 级告警，按频次排序，取 TOP 8
    topAlerts.value = Array.from(groups.entries())
      .filter(([, v]) => v.maxLevel >= 7)
      .map(([label, v]) => ({
        label,
        count: v.count,
        level: v.maxLevel,
        ruleId: v.ruleId
      }))
      .sort((a, b) => b.count - a.count || b.level - a.level)
      .slice(0, 8);
  } catch (err) {
    console.error('获取高频告警失败', err);
  } finally {
    topLoading.value = false;
  }
};

// 取色函数：根据 level 返回颜色
const levelColor = (level: number) => {
  if (level >= 13) return '#f5023d';
  if (level >= 10) return '#e3b337';
  if (level >= 7)  return '#31ABE3';
  return '#7c8a9e';
};

// 按数量缩放字体大小（词云效果）
const fontSizeByCount = (count: number, maxCount: number) => {
  const min = 11, max = 18;
  if (maxCount === 0) return min;
  return Math.round(min + (count / maxCount) * (max - min));
};

// 最大 count（用于字体缩放）
const maxCount = computed(() => {
  if (topAlerts.value.length === 0) return 0;
  return Math.max(...topAlerts.value.map(a => a.count));
});

// ── 导航到第二页告警查询 ──
const navigateToAlerts = () => {
  window.dispatchEvent(new CustomEvent('navigate-to-alerts'));
};

onMounted(() => {
  fetchTopAlerts();
});
</script>

<template>
  <div class="rc-root">
    <div class="rc-header">
      <span class="rc-header-icon">🔥</span>
      <span class="rc-header-title">高频告警 TOP 8</span>
      <span class="rc-header-badge">24h</span>
    </div>

    <!-- 词云区域 -->
    <div class="rc-top-content">
      <div v-if="topLoading" class="rc-loading-hint">加载中...</div>
      <div v-else-if="topAlerts.length === 0" class="rc-empty-hint">近 24 小时暂无告警数据</div>
      <div v-else class="rc-tag-cloud">
        <span
          v-for="(item, idx) in topAlerts"
          :key="idx"
          class="rc-tag"
          :style="{
            fontSize: fontSizeByCount(item.count, maxCount) + 'px',
            borderColor: levelColor(item.level),
            color: levelColor(item.level)
          }"
          :title="`${item.label} · Level ${item.level} · 出现 ${item.count} 次`"
        >
          <span class="rc-tag-text">{{ item.label }}</span>
          <sup class="rc-tag-count">{{ item.count }}</sup>
        </span>
      </div>
    </div>

    <!-- 导航按钮 -->
    <button class="rc-goto" @click="navigateToAlerts">
      查看全部告警
      <span class="rc-goto-arrow">→</span>
    </button>
  </div>
</template>

<style scoped lang="scss">
.rc-root {
  height: 100%;
  display: flex;
  flex-direction: column;
  box-sizing: border-box;
  padding: 4px 0;
}

// ── Header ──
.rc-header {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 2px 0 8px;
  border-bottom: 1px solid rgba(49, 171, 227, 0.08);
  flex-shrink: 0;

  .rc-header-icon { font-size: 14px; line-height: 1; }
  .rc-header-title {
    font-size: 12px;
    font-weight: 600;
    color: rgba(255, 255, 255, 0.6);
    letter-spacing: 0.5px;
  }
  .rc-header-badge {
    margin-left: auto;
    font-size: 10px;
    font-weight: 600;
    font-family: ui-monospace, monospace;
    color: rgba(49, 171, 227, 0.7);
    background: rgba(49, 171, 227, 0.08);
    padding: 1px 8px;
    border-radius: 999px;
  }
}

// ── 词云内容 ──
.rc-top-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  padding: 4px 0;
  min-height: 0;
}

.rc-loading-hint,
.rc-empty-hint {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  color: rgba(255, 255, 255, 0.2);
}

.rc-tag-cloud {
  flex: 1;
  display: flex;
  flex-wrap: wrap;
  align-content: center;
  gap: 8px 10px;
  padding: 4px 0;
  overflow-y: auto;
}

.rc-tag {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 10px;
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid;
  border-radius: 999px;
  font-weight: 500;
  transition: all 0.2s ease;
  line-height: 1.4;
  cursor: default;
  max-width: 100%;

  &:hover {
    background: rgba(255, 255, 255, 0.05);
    box-shadow: 0 0 10px currentColor;
  }

  .rc-tag-text {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 140px;
  }
}

.rc-tag-count {
  font-size: 10px;
  font-weight: 700;
  font-family: ui-monospace, monospace;
  opacity: 0.7;
  line-height: 1;
  flex-shrink: 0;
}

// ── 导航按钮 ──
.rc-goto {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  width: 100%;
  padding: 6px 0;
  background: rgba(49, 171, 227, 0.06);
  border: 1px solid rgba(49, 171, 227, 0.15);
  color: #31ABE3;
  font-size: 12px;
  font-weight: 600;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.25s ease;
  flex-shrink: 0;
  margin-top: 4px;

  &:hover {
    background: rgba(49, 171, 227, 0.12);
    border-color: rgba(49, 171, 227, 0.3);
    gap: 10px;
  }

  .rc-goto-arrow {
    font-size: 14px;
    transition: transform 0.25s ease;
  }

  &:hover .rc-goto-arrow {
    transform: translateX(3px);
  }
}
</style>
