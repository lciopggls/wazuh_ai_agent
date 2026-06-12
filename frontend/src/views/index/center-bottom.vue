<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount } from "vue";
import { ElMessage } from "element-plus";
import axios from 'axios';
import CountUp from "@/components/count-up";

// ── Wazuh 认证 ──
const wazuhUser = import.meta.env.VITE_WAZUH_SERVER_API_USERNAME;
const wazuhPass = import.meta.env.VITE_WAZUH_SERVER_API_PASSWORD;
const AUTH_PAYLOAD = btoa(`${wazuhUser}:${wazuhPass}`);

// ── 状态 ──
const totalRules = ref(0);
const highRiskRules = ref(0);
const loading = ref(false);
const error = ref(false);
const duration = ref(2);

const HIGH_RISK_THRESHOLD = 12; // level >= 12 视为高危

let refreshTimer: any = null;

// ── 计算属性 ──
const highRiskPercent = computed(() => {
  if (totalRules.value === 0) return 0;
  return +(highRiskRules.value / totalRules.value * 100).toFixed(1);
});

const riskLevelText = computed(() => {
  const p = highRiskPercent.value;
  if (p >= 30) return { label: '高风险', color: '#f5023d' };
  if (p >= 15) return { label: '中风险', color: '#e3b337' };
  return { label: '低风险', color: '#07f7a8' };
});

// ── 认证 ──
const authenticate = async () => {
  try {
    const res = await axios.get('/wazuh-api/security/user/authenticate', {
      headers: { 'Authorization': `Basic ${AUTH_PAYLOAD}` }
    });
    return res.data.data.token;
  } catch (err) {
    ElMessage.error("Wazuh 认证失败");
    return null;
  }
};

// ── 获取规则数据（本地计算高危占比） ──
const fetchRules = async (isRetry = false) => {
  loading.value = true;
  error.value = false;

  const token = await authenticate();
  if (!token) {
    loading.value = false;
    error.value = true;
    return;
  }

  try {
    const res = await axios.get('/wazuh-api/rules', {
      params: { limit: 10000, sort: '-level' },
      headers: { 'Authorization': `Bearer ${token}` }
    });

    const items: any[] = res.data.data?.affected_items || [];
    totalRules.value = items.length;
    highRiskRules.value = items.filter(r => Number(r.level) >= HIGH_RISK_THRESHOLD).length;
  } catch (err: any) {
    if (err.response?.status === 401 && !isRetry) {
      await fetchRules(true);
      return;
    }
    error.value = true;
    console.error("规则数据获取失败:", err);
  } finally {
    loading.value = false;
  }
};

// ── 页面导航 ──
const navigateToRules = () => {
  window.dispatchEvent(new CustomEvent('navigate-to-rules'));
};

// ── 生命周期 ──
onMounted(() => {
  fetchRules();
  refreshTimer = setInterval(fetchRules, 60000);
});

onBeforeUnmount(() => {
  if (refreshTimer) clearInterval(refreshTimer);
});
</script>

<template>
  <div class="risk-dashboard">
    <!-- 加载遮罩 -->
    <div v-if="loading && totalRules === 0" class="loading-overlay">
      <div class="loader"></div>
      <span>正在采集规则数据...</span>
    </div>

    <!-- 错误提示 -->
    <div v-else-if="error && totalRules === 0" class="error-overlay">
      <span class="error-icon">⚠</span>
      <span>数据获取失败，请检查 Wazuh API 连接</span>
      <button class="retry-btn" @click="fetchRules()">重试</button>
    </div>

    <!-- 主内容 -->
    <template v-else>
      <!-- 顶部指标卡片 -->
      <div class="stats-row">
        <div class="stat-card">
          <div class="stat-label">
            <span class="stat-icon">📜</span>
            <span>规则总数</span>
          </div>
          <div class="stat-value stat-value--total">
            <CountUp :endVal="totalRules" :duration="duration" />
          </div>
          <div class="stat-footer">Total Rules</div>
        </div>

        <div class="stat-card">
          <div class="stat-label">
            <span class="stat-icon">🔴</span>
            <span>高危规则</span>
          </div>
          <div class="stat-value stat-value--highrisk">
            <CountUp :endVal="highRiskRules" :duration="duration" />
          </div>
          <div class="stat-footer">High-Risk Rules (Level ≥ {{ HIGH_RISK_THRESHOLD }})</div>
        </div>
      </div>

      <!-- 进度条区域 -->
      <div class="progress-section">
        <div class="progress-header">
          <span class="progress-title">高危占比</span>
          <div class="progress-meta">
            <span class="progress-percent" :style="{ color: riskLevelText.color }">
              {{ highRiskPercent }}%
            </span>
            <span class="risk-badge" :style="{ background: riskLevelText.color + '22', color: riskLevelText.color, borderColor: riskLevelText.color + '44' }">
              {{ riskLevelText.label }}
            </span>
          </div>
        </div>

        <div class="progress-track">
          <div
            class="progress-fill"
            :style="{ width: highRiskPercent + '%', background: riskLevelText.color, boxShadow: `0 0 12px ${riskLevelText.color}66` }"
          ></div>
          <div class="progress-glow" :style="{ background: riskLevelText.color }"></div>
        </div>

        <div class="progress-legend">
          <span class="legend-item">
            <span class="legend-dot" style="background: #31ABE3;"></span>
            低危 (Level &lt; {{ HIGH_RISK_THRESHOLD }})
          </span>
          <span class="legend-item">
            <span class="legend-dot" :style="{ background: riskLevelText.color }"></span>
            高危 (Level ≥ {{ HIGH_RISK_THRESHOLD }})
          </span>
        </div>
      </div>

      <!-- 底部操作栏 -->
      <div class="action-bar">
        <div class="update-bar">
          <span class="update-dot" :class="{ 'update-dot--error': error }"></span>
          <span class="update-text">{{ error ? '数据异常' : '实时更新中' }}</span>
        </div>
        <button class="nav-btn" @click="navigateToRules">
          <span class="nav-btn-icon">📜</span>
          <span>查询所有规则</span>
          <span class="nav-btn-arrow">→</span>
        </button>
      </div>
    </template>
  </div>
</template>

<style scoped lang="scss">
.risk-dashboard {
  position: relative;
  width: 100%;
  height: 100%;
  padding: 18px 16px 12px;
  display: flex;
  flex-direction: column;
  gap: 16px;
  box-sizing: border-box;
  min-height: 0;
}

// ── Loading / Error ──
.loading-overlay,
.error-overlay {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  color: var(--muted-foreground, #7c8a9e);
  font-size: 12px;
}

.loader {
  width: 28px;
  height: 28px;
  border: 2px solid rgba(49, 171, 227, 0.15);
  border-top-color: #31ABE3;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

.error-icon {
  font-size: 24px;
  opacity: 0.6;
}

.retry-btn {
  margin-top: 4px;
  padding: 4px 16px;
  background: transparent;
  border: 1px solid #31ABE3;
  color: #31ABE3;
  border-radius: 4px;
  cursor: pointer;
  font-size: 11px;
  transition: 0.2s;
  &:hover {
    background: rgba(49, 171, 227, 0.1);
  }
}

// ── Stat Cards Row ──
.stats-row {
  display: flex;
  gap: 12px;
  flex-shrink: 0;
}

.stat-card {
  flex: 1;
  background: var(--card, #111827);
  border: 1px solid var(--border, rgba(49, 171, 227, 0.12));
  border-radius: 8px;
  padding: 14px 16px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  transition: border-color 0.2s;

  &:hover {
    border-color: rgba(49, 171, 227, 0.3);
  }
}

.stat-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-weight: 500;
  color: var(--muted-foreground, #7c8a9e);

  .stat-icon {
    font-size: 14px;
    line-height: 1;
  }
}

.stat-value {
  font-family: 'Consolas', 'Fira Code', monospace;
  font-size: 32px;
  font-weight: 800;
  line-height: 1.1;
  letter-spacing: 1px;

  &--total {
    color: #00fdfa;
    text-shadow: 0 0 20px rgba(0, 253, 250, 0.2);
  }

  &--highrisk {
    color: #ff4d4f;
    text-shadow: 0 0 20px rgba(255, 77, 79, 0.2);
  }
}

.stat-footer {
  font-size: 10px;
  color: var(--muted-foreground, #7c8a9e);
  opacity: 0.5;
  font-family: ui-monospace, monospace;
  letter-spacing: 0.3px;
}

// ── Progress Section ──
.progress-section {
  flex: 1;
  background: var(--card, #111827);
  border: 1px solid var(--border, rgba(49, 171, 227, 0.12));
  border-radius: 8px;
  padding: 16px 18px;
  display: flex;
  flex-direction: column;
  gap: 14px;
  min-height: 0;
  transition: border-color 0.2s;

  &:hover {
    border-color: rgba(49, 171, 227, 0.3);
  }
}

.progress-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.progress-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--foreground, #d3d6dd);
  letter-spacing: 0.5px;
}

.progress-meta {
  display: flex;
  align-items: center;
  gap: 10px;
}

.progress-percent {
  font-family: 'Consolas', 'Fira Code', monospace;
  font-size: 20px;
  font-weight: 800;
  transition: color 0.3s;
}

.risk-badge {
  font-size: 10px;
  font-weight: 600;
  padding: 2px 10px;
  border-radius: 999px;
  border: 1px solid;
  letter-spacing: 0.5px;
}

// ── Progress Track ──
.progress-track {
  position: relative;
  width: 100%;
  height: 18px;
  background: rgba(255, 255, 255, 0.04);
  border-radius: 999px;
  overflow: hidden;
  border: 1px solid rgba(255, 255, 255, 0.04);
  flex-shrink: 0;
}

.progress-fill {
  position: absolute;
  top: 0;
  left: 0;
  height: 100%;
  border-radius: 999px;
  transition: width 1.2s cubic-bezier(0.4, 0, 0.2, 1), background 0.6s;
  z-index: 2;
}

.progress-glow {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  border-radius: 999px;
  opacity: 0.08;
  z-index: 1;
}

// ── Legend ──
.progress-legend {
  display: flex;
  align-items: center;
  gap: 20px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 10.5px;
  color: var(--muted-foreground, #7c8a9e);
}

.legend-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

// ── Action Bar ──
.action-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
  padding-top: 2px;
}

.nav-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 14px;
  background: rgba(49, 171, 227, 0.08);
  border: 1px solid rgba(49, 171, 227, 0.2);
  border-radius: 6px;
  color: #31ABE3;
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.25s ease;
  user-select: none;
  line-height: 1;

  .nav-btn-icon {
    font-size: 13px;
    line-height: 1;
  }

  .nav-btn-arrow {
    font-size: 14px;
    transition: transform 0.25s ease;
  }

  &:hover {
    background: rgba(49, 171, 227, 0.16);
    border-color: rgba(49, 171, 227, 0.4);
    box-shadow: 0 0 14px rgba(49, 171, 227, 0.08);
    color: #00fdfa;

    .nav-btn-arrow {
      transform: translateX(3px);
    }
  }

  &:active {
    background: rgba(49, 171, 227, 0.22);
    transform: scale(0.98);
  }
}

// ── Update Bar ──
.update-bar {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}

.update-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #07f7a8;
  animation: pulse-dot 2s ease-in-out infinite;

  &--error {
    background: #e3b337;
  }
}

.update-text {
  font-size: 10px;
  color: var(--muted-foreground, #7c8a9e);
  opacity: 0.4;
  letter-spacing: 0.3px;
}

// ── Keyframes ──
@keyframes spin {
  to { transform: rotate(360deg); }
}

@keyframes pulse-dot {
  0%, 100% { opacity: 0.3; }
  50% { opacity: 1; }
}
</style>
