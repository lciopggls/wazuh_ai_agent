<script setup lang="ts">
import { ref } from "vue";

defineProps<{
  svgs?: {
    svgChart: string | null;
    attackGraph: string | null;
  }
}>();

// SVG 全屏预览
const isSvgModalOpen = ref(false);
const svgModalTitle = ref('');
const currentSvgContent = ref('');

const openSvgPreview = (title: string, svgRaw: string | null | undefined) => {
  if (!svgRaw) return;
  svgModalTitle.value = title;
  currentSvgContent.value = svgRaw;
  isSvgModalOpen.value = true;
};
</script>

<template>
  <div class="tp-root flex flex-col h-full">
    <!-- Tool Bar -->
    <div class="tp-toolbar flex items-center flex-shrink-0 px-4 py-3">
      <div class="flex items-center gap-1.5">
        <span class="toolbar-badge">🕸️ 拓扑可视化</span>
        <span class="toolbar-hint">SVG 攻击链与网络拓扑图</span>
      </div>
    </div>

    <div class="tp-body flex-1 overflow-y-auto px-4 pb-4">
      <div class="resources-area flex flex-col h-full">
        <div class="mb-3">
          <h4 class="text-sm font-semibold text-[#1d4ed8] m-0">🛡️ 安全线程可视化图谱</h4>
          <p class="text-xs text-[var(--muted-foreground)] mt-1 mb-0 opacity-60">
            系统在溯源分析过程中生成的结构图，点击按钮查看完整大图
          </p>
        </div>

        <!-- 图谱卡片容器 -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2">
          <!-- SVG Chart Card -->
          <div
            :class="['graph-card', svgs?.svgChart ? 'graph-card--active' : 'graph-card--empty']"
            @click="svgs?.svgChart && openSvgPreview('分析流转卡片图 (SVG_CHART)', svgs?.svgChart)"
          >
            <div class="graph-card-header">
              <span class="graph-icon">📊</span>
              <div>
                <div class="graph-title">分析流转图</div>
                <div class="graph-desc">安全分析流程与数据流转卡片</div>
              </div>
              <div v-if="svgs?.svgChart" class="graph-status status-ready">已就绪</div>
              <div v-else class="graph-status status-pending">等待中</div>
            </div>
            <div class="graph-card-body">
              <div v-if="svgs?.svgChart" class="graph-preview">
                <div class="preview-icon">🔍</div>
                <span>点击查看完整大图</span>
              </div>
              <div v-else class="graph-preview graph-preview--empty">
                <div class="empty-pulse"></div>
                <span>请先执行攻击溯源分析</span>
              </div>
            </div>
          </div>

          <!-- Attack Graph Card -->
          <div
            :class="['graph-card', svgs?.attackGraph ? 'graph-card--active' : 'graph-card--empty']"
            @click="svgs?.attackGraph && openSvgPreview('溯源攻击拓扑图 (ATTACK_GRAPH)', svgs?.attackGraph)"
          >
            <div class="graph-card-header">
              <span class="graph-icon">🕸️</span>
              <div>
                <div class="graph-title">攻击拓扑图</div>
                <div class="graph-desc">溯源攻击链路与主机关系图谱</div>
              </div>
              <div v-if="svgs?.attackGraph" class="graph-status status-ready">已就绪</div>
              <div v-else class="graph-status status-pending">等待中</div>
            </div>
            <div class="graph-card-body">
              <div v-if="svgs?.attackGraph" class="graph-preview">
                <div class="preview-icon">🕸️</div>
                <span>点击查看完整大图</span>
              </div>
              <div v-else class="graph-preview graph-preview--empty">
                <div class="empty-pulse"></div>
                <span>请先执行攻击溯源分析</span>
              </div>
            </div>
          </div>
        </div>

        <!-- 提示区 -->
        <div v-if="!svgs?.svgChart && !svgs?.attackGraph" class="resource-hint">
          💡 提示：当前对话内尚未发现可用的拓扑数据。请在右侧 AI 窗口内让智能体执行攻击溯源任务，图谱将自动在此同步。
        </div>
        <div v-else class="resource-hint resource-hint--ok">
          ✅ 拓扑数据已加载，点击卡片即可预览完整 SVG 矢量图。
        </div>
      </div>
    </div>

    <!-- ── SVG Fullscreen Modal ── -->
    <Teleport to="body">
      <div v-if="isSvgModalOpen" class="svg-backdrop" @click.self="isSvgModalOpen = false">
        <div class="svg-window">
          <div class="svg-header">
            <span class="text-sm font-bold text-[#1d4ed8]">{{ svgModalTitle }}</span>
            <button class="svg-close" @click="isSvgModalOpen = false">✕</button>
          </div>
          <div class="svg-body" v-html="currentSvgContent"></div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped lang="scss">
// ── Root ──
.tp-root {
  background: #ffffff;
  border-radius: 8px;
  border: 1px solid #e5e7eb;
  position: relative;
  overflow: hidden;
  height: 100%;
}

// ── Toolbar ──
.tp-toolbar {
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
.tp-body {
  &::-webkit-scrollbar { width: 3px; }
  &::-webkit-scrollbar-thumb {
    background: color-mix(in oklab, var(--muted-foreground, #7c8a9e) 15%, transparent);
    border-radius: 2px;
  }
}

// ── Graph Cards ──
.graph-card {
  border-radius: 8px;
  overflow: hidden;
  transition: all 0.3s ease;

  &--active {
    background: #ffffff;
    border: 1px solid #e5e7eb;
    cursor: pointer;

    &:hover {
      border-color: rgba(29, 78, 216, 0.2);
      box-shadow: 0 0 20px rgba(29, 78, 216, 0.06);
      transform: translateY(-2px);
    }
  }

  &--empty {
    background: transparent;
    border: 1px dashed var(--border, rgba(49, 171, 227, 0.12));
    opacity: 0.6;
  }
}

.graph-card-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 14px;
  background: #f8fafc;
  border-bottom: 1px solid #e5e7eb;

  .graph-icon {
    font-size: 20px;
    line-height: 1;
    flex-shrink: 0;
  }

  .graph-title {
    font-size: 13px;
    font-weight: 600;
    color: #374151;
  }

  .graph-desc {
    font-size: 10px;
    color: var(--muted-foreground, #7c8a9e);
    margin-top: 1px;
  }
}

.graph-status {
  margin-left: auto;
  font-size: 9.5px;
  font-weight: 600;
  padding: 2px 10px;
  border-radius: 999px;
  font-family: ui-monospace, monospace;
  flex-shrink: 0;

  &.status-ready {
    background: rgba(29, 78, 216, 0.06);
    color: #1d4ed8;
    border: 1px solid rgba(29, 78, 216, 0.12);
  }

  &.status-pending {
    background: rgba(227, 179, 55, 0.06);
    color: #e3b337;
    border: 1px solid rgba(227, 179, 55, 0.1);
  }
}

.graph-card-body {
  padding: 20px 14px;
}

.graph-preview {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 12px;
  border-radius: 6px;
  font-size: 12px;
  color: var(--muted-foreground, #7c8a9e);

  .preview-icon {
    font-size: 18px;
  }

  &--empty {
    flex-direction: column;
    gap: 10px;
    padding: 16px;
  }
}

.empty-pulse {
  width: 24px;
  height: 24px;
  border: 2px solid color-mix(in oklab, var(--muted-foreground, #7c8a9e) 10%, transparent);
  border-top-color: #1d4ed8;
  border-radius: 50%;
  animation: radarSpin 1s linear infinite;
}

// ── Hint ──
.resource-hint {
  margin-top: 16px;
  background: rgba(227, 179, 55, 0.04);
  border: 1px dashed rgba(227, 179, 55, 0.15);
  padding: 10px 14px;
  border-radius: 8px;
  font-size: 11px;
  color: #e3b337;
  line-height: 1.5;

  &--ok {
    background: rgba(29, 78, 216, 0.03);
    border-color: rgba(29, 78, 216, 0.12);
    color: #1d4ed8;
  }
}

// ── SVG Modal ──
.svg-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(8px);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 99999;
}

.svg-window {
  width: 88vw;
  height: 88vh;
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);
}

.svg-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 20px;
  background: #f0f7ff;
  border-bottom: 1px solid #e5e7eb;
  flex-shrink: 0;
}

.svg-close {
  background: none;
  border: none;
  color: #6b7280;
  font-size: 18px;
  cursor: pointer;
  padding: 4px 8px;
  border-radius: 4px;
  transition: all 0.2s ease;

  &:hover {
    color: #fff;
    background: rgba(255, 255, 255, 0.05);
  }
}

.svg-body {
  flex: 1;
  padding: 20px;
  overflow: auto;
  display: flex;
  justify-content: center;
  align-items: center;
  background: #f8fafc;

  :deep(svg) {
    max-width: 100%;
    max-height: 100%;
    width: auto;
    height: auto;
  }
}

@keyframes radarSpin {
  to { transform: rotate(360deg); }
}
</style>
