<script setup lang="ts">
defineProps<{
  attackAbstract?: {
    hosts?: string[];
    start_time?: string;
    end_time?: string;
    duration?: string;
    ioc_files?: string[];
    ioc_domains?: string[];
    ioc_processes?: string[];
    tactics?: string[];
    tactics_count?: number;
  } | null;
}>();
</script>

<template>
  <div class="ts-root flex flex-col h-full">
    <div class="ts-toolbar flex items-center flex-shrink-0 px-4 py-3">
      <div class="flex items-center gap-1.5">
        <span class="toolbar-badge">📋 攻击归因分析</span>
        <span class="toolbar-hint">受影响的资产与威胁情报 IOC</span>
      </div>
    </div>

    <div class="ts-body flex-1 overflow-y-auto px-4 pb-4">
      <div v-if="attackAbstract" class="flex flex-col gap-4">
        <!-- Hosts -->
        <div class="summary-card">
          <div class="summary-card-header">
            <span class="card-icon">🖥️</span>
            <span>受影响主机资产</span>
            <span class="card-badge">Hosts</span>
          </div>
          <div class="summary-card-body">
            <div v-if="attackAbstract.hosts && attackAbstract.hosts.length > 0" class="flex flex-wrap gap-2">
              <span v-for="(host, idx) in attackAbstract.hosts" :key="idx" class="host-chip">
                <span class="host-chip-icon">🖥</span>
                {{ host }}
              </span>
            </div>
            <p v-else class="summary-empty">暂无受影响主机数据</p>
          </div>
        </div>

        <!-- Timing -->
        <div class="summary-card">
          <div class="summary-card-header">
            <span class="card-icon">⏱️</span>
            <span>攻击事件计时</span>
            <span class="card-badge">Timeline</span>
          </div>
          <div class="summary-card-body">
            <div class="grid grid-cols-2 gap-3">
              <div class="time-stat">
                <span class="time-stat-label">开始时间</span>
                <span class="time-stat-value">{{ attackAbstract.start_time || '--' }}</span>
              </div>
              <div class="time-stat">
                <span class="time-stat-label">结束时间</span>
                <span class="time-stat-value">{{ attackAbstract.end_time || '--' }}</span>
              </div>
              <div class="col-span-2 time-stat time-stat--full">
                <span class="time-stat-label">持续时长</span>
                <span class="time-stat-value text-[#ffeb3b] font-bold">⏳ {{ attackAbstract.duration || '0秒' }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- IOC -->
        <div class="summary-card">
          <div class="summary-card-header">
            <span class="card-icon">🔍</span>
            <span>威胁情报 IOC</span>
            <span class="card-badge">Indicators</span>
          </div>
          <div class="summary-card-body flex flex-col gap-4">
            <div class="ioc-section">
              <div class="ioc-section-header">
                <span>📁 恶意文件</span>
                <span class="ioc-count">{{ attackAbstract.ioc_files?.length || 0 }}</span>
              </div>
              <div class="ioc-tags">
                <span v-for="(file, i) in attackAbstract.ioc_files" :key="i" class="ioc-tag ioc-tag--file">{{ file }}</span>
                <span v-if="!attackAbstract.ioc_files?.length" class="ioc-none">无关联文件</span>
              </div>
            </div>
            <div class="ioc-section">
              <div class="ioc-section-header">
                <span>⚙️ 恶意进程</span>
                <span class="ioc-count">{{ attackAbstract.ioc_processes?.length || 0 }}</span>
              </div>
              <div class="ioc-tags">
                <span v-for="(proc, i) in attackAbstract.ioc_processes" :key="i" class="ioc-tag ioc-tag--proc">{{ proc }}</span>
                <span v-if="!attackAbstract.ioc_processes?.length" class="ioc-none">无关联进程</span>
              </div>
            </div>
            <div class="ioc-section">
              <div class="ioc-section-header">
                <span>🌐 恶意域名</span>
                <span class="ioc-count">{{ attackAbstract.ioc_domains?.length || 0 }}</span>
              </div>
              <div class="ioc-tags">
                <span v-for="(dom, i) in attackAbstract.ioc_domains" :key="i" class="ioc-tag ioc-tag--domain">{{ dom }}</span>
                <span v-if="!attackAbstract.ioc_domains?.length" class="ioc-none">无关联网络域名</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Empty state -->
      <div v-else class="flex flex-col items-center justify-center py-20 text-center gap-3">
        <div class="radar-spinner"></div>
        <p class="text-sm font-medium text-[var(--muted-foreground)]">等待智能体生成战术简报数据...</p>
        <span class="text-xs text-[var(--muted-foreground)] opacity-50 max-w-[260px] leading-relaxed">
          右侧 AI 窗口吐出溯源数据后，此处将自动解析并刷新大屏卡片。
        </span>
      </div>
    </div>
  </div>
</template>

<style scoped lang="scss">
// ── Root ──
.ts-root {
  background: #ffffff;
  border-radius: 8px;
  border: 1px solid #e5e7eb;
  position: relative;
  overflow: hidden;
  height: 100%;
}

// ── Toolbar ──
.ts-toolbar {
  border-bottom: 1px solid #e5e7eb;
  background: #f8fafc;
}

.toolbar-badge {
  font-size: 12px;
  font-weight: 600;
  color: #1d4ed8;
  background: rgba(29, 78, 216, 0.06);
  padding: 3px 12px;
  border-radius: 999px;
  border: 1px solid rgba(29, 78, 216, 0.1);
}

.toolbar-hint {
  font-size: 11px;
  color: var(--muted-foreground, #7c8a9e);
  margin-left: 8px;
  opacity: 0.6;
}

// ── Body ──
.ts-body {
  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb {
    background: color-mix(in oklab, var(--muted-foreground, #7c8a9e) 15%, transparent);
    border-radius: 2px;
  }
}

// ── Summary Cards ──
.summary-card {
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  overflow: hidden;
  transition: all 0.2s ease;

  &:hover {
    border-color: color-mix(in oklab, #e5e7eb 60%, #31ABE3);
  }
}

.summary-card-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 9px 14px;
  font-size: 12px;
  font-weight: 600;
  color: #1d4ed8;
  background: #f8fafc;
  border-bottom: 1px solid #e5e7eb;

  .card-icon { font-size: 14px; line-height: 1; }

  .card-badge {
    margin-left: auto;
    font-size: 9.5px;
    font-weight: 600;
    font-family: ui-monospace, monospace;
    color: var(--muted-foreground, #7c8a9e);
    background: #f3f4f6;
    padding: 1px 8px;
    border-radius: 999px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }
}

.summary-card-body {
  padding: 12px 14px;
}

.summary-empty {
  font-size: 11px;
  color: var(--muted-foreground, #7c8a9e);
  font-style: italic;
  text-align: center;
  margin: 0;
  padding: 4px 0;
}

// ── Host Chips ──
.host-chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 5px 12px;
  font-family: ui-monospace, monospace;
  font-size: 11.5px;
  color: #374151;
  background: #f8fafc;
  border: 1px dashed #e5e7eb;
  border-radius: 6px;
  transition: all 0.2s ease;

  .host-chip-icon { font-size: 12px; opacity: 0.6; }

  &:hover {
    border-color: rgba(49, 171, 227, 0.3);
    background: rgba(49, 171, 227, 0.08);
  }
}

// ── Time Stats ──
.time-stat {
  display: flex;
  flex-direction: column;
  gap: 3px;
  padding: 8px 10px;
  background: #f8fafc;
  border: 1px solid #e5e7eb;
  border-radius: 6px;

  .time-stat-label {
    font-size: 10px;
    color: var(--muted-foreground, #7c8a9e);
    font-weight: 500;
  }

  .time-stat-value {
    font-size: 12px;
    color: #374151;
    font-family: ui-monospace, monospace;
  }

  &--full {
    flex-direction: row;
    justify-content: space-between;
    align-items: center;
  }
}

// ── IOC Sections ──
.ioc-section {
  display: flex;
  flex-direction: column;
  gap: 6px;

  .ioc-section-header {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    font-weight: 600;
    color: #374151;

    .ioc-count {
      font-family: ui-monospace, monospace;
      font-size: 10px;
      color: var(--muted-foreground, #7c8a9e);
      background: #f3f4f6;
      padding: 0 6px;
      border-radius: 999px;
      line-height: 1.5;
    }
  }
}

.ioc-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.ioc-tag {
  font-family: ui-monospace, monospace;
  font-size: 10.5px;
  padding: 2px 8px;
  border-radius: 4px;
  transition: all 0.15s ease;

  &--file {
    color: #374151;
    background: rgba(0, 0, 0, 0.02);
    border: 1px solid #e5e7eb;
    &:hover { border-color: rgba(49, 171, 227, 0.3); }
  }

  &--proc {
    color: #ffb74d;
    background: rgba(255, 183, 77, 0.04);
    border: 1px solid rgba(255, 183, 77, 0.15);
    &:hover { border-color: rgba(255, 183, 77, 0.35); }
  }

  &--domain {
    color: #4fc3f7;
    background: rgba(79, 195, 247, 0.04);
    border: 1px solid rgba(79, 195, 247, 0.15);
    &:hover { border-color: rgba(79, 195, 247, 0.35); }
  }
}

.ioc-none {
  font-size: 10.5px;
  color: var(--muted-foreground, #7c8a9e);
  opacity: 0.4;
  font-style: italic;
}

// ── Empty State ──
.radar-spinner {
  width: 34px;
  height: 34px;
  border: 3px solid color-mix(in oklab, #31ABE3 10%, transparent);
  border-top-color: #1d4ed8;
  border-radius: 50%;
  animation: radarSpin 1s linear infinite;
}

@keyframes radarSpin {
  to { transform: rotate(360deg); }
}
</style>
