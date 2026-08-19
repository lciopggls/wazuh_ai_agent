<script setup lang="ts">
import type { ComparisonResponse } from "@/api/report_scoring";

defineProps<{ comparison: ComparisonResponse | null }>();

const dimensions = [
  ["anchor_accuracy", "锚点"],
  ["evidence_recall", "召回"],
  ["timeline", "时间线"],
  ["process_chain", "进程链"],
  ["mitre_mapping", "MITRE"],
  ["negative_findings", "负面结论"],
] as const;

const display = (value: number | null) => value == null ? "—" : value.toFixed(1);
</script>

<template>
  <section class="card comparison-card">
    <div class="title"><h3>多智能体对比</h3><span v-if="comparison">{{ comparison.test_case_id }} · {{ comparison.scoring_standard_version }}</span></div>
    <div v-if="!comparison" class="empty">选择案例后加载对比。</div>
    <div v-else class="table-wrap">
      <table>
        <thead><tr><th>智能体</th><th>已登记 / 有效评分</th><th>各报告最新总分</th><th>平均</th><th>最低</th><th>最高</th><th v-for="[, label] in dimensions" :key="label">{{ label }}</th></tr></thead>
        <tbody><tr v-for="agent in comparison.agents" :key="agent.agent_id"><td><strong>{{ agent.display_name }}</strong><small>{{ agent.agent_id }}</small></td><td>{{ agent.registered_report_count }} / {{ agent.successfully_scored_report_count }}</td><td>{{ agent.report_scores.length ? agent.report_scores.map(item => item.total_score.toFixed(1)).join(' / ') : '—' }}</td><td class="average">{{ display(agent.average_total) }}</td><td>{{ display(agent.minimum_total) }}</td><td>{{ display(agent.maximum_total) }}</td><td v-for="[key] in dimensions" :key="key">{{ display(agent.dimension_averages[key]) }}</td></tr></tbody>
      </table>
    </div>
  </section>
</template>

<style scoped lang="scss">
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px; }
.title { display: flex; justify-content: space-between; margin-bottom: 10px; h3 { margin: 0; font-size: 15px; color: #1f2937; } span { color: #64748b; font-size: 12px; } }
.table-wrap { overflow-x: auto; }
table { min-width: 1100px; width: 100%; border-collapse: collapse; font-size: 12px; }
th, td { padding: 8px; border-bottom: 1px solid #e5e7eb; text-align: center; color: #475569; }
th:first-child, td:first-child { text-align: left; }
td strong, td small { display: block; } td small { color: #94a3b8; margin-top: 3px; }
.average { color: #1d4ed8; font-weight: 800; }
.empty { color: #94a3b8; padding: 18px 0; text-align: center; }
</style>
