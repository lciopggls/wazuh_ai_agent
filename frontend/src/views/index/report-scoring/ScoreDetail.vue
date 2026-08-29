<script setup lang="ts">
import { computed } from "vue";
import {
  REPORT_SCORE_DIMENSIONS,
  type ReportRecord,
  type ScoreHistoryItem,
  type ScoreResult,
} from "@/api/report_scoring";

const props = defineProps<{
  report: ReportRecord | null;
  result: ScoreResult | null;
  history: ScoreHistoryItem[];
}>();

const dimensions = computed(() => {
  if (!props.result) return [];
  const score = props.result.score;
  return REPORT_SCORE_DIMENSIONS.map(({ key, label, maximum }) => [
    label,
    score[key],
    maximum,
  ] as const);
});
</script>

<template>
  <section class="card detail-card">
    <h3>单报告评分详情</h3>
    <div v-if="!report" class="empty">选择一份报告查看详情。</div>
    <template v-else>
      <div class="report-meta"><strong>{{ report.original_filename }}</strong><code>{{ report.report_id }}</code></div>
      <div v-if="!result" class="empty">该报告尚无成功评分；失败记录仍会保留在下方历史中。</div>
      <template v-else>
        <div class="score-header">
          <div class="total"><b>{{ result.total_score.toFixed(1) }}</b><span>/ 100</span></div>
          <div><strong>{{ result.scoring_standard_version }}</strong><small>{{ result.model_name }} · {{ new Date(result.completed_at).toLocaleString() }}</small></div>
        </div>
        <div class="dimension-grid">
          <article v-for="([name, item, maximum]) in dimensions" :key="name">
            <header><strong>{{ name }}</strong><b>{{ item.score.toFixed(1) }} / {{ maximum }}</b></header>
            <p>{{ item.reason }}</p>
          </article>
        </div>
        <div class="conclusions">
          <div><h4>做得好的地方</h4><ul><li v-for="item in result.score.strengths" :key="item">{{ item }}</li><li v-if="!result.score.strengths.length">—</li></ul></div>
          <div><h4>主要问题</h4><ul><li v-for="item in result.score.major_issues" :key="item">{{ item }}</li><li v-if="!result.score.major_issues.length">—</li></ul></div>
        </div>
      </template>
      <div class="history">
        <h4>评分历史</h4>
        <div v-if="!history.length" class="muted">暂无评分尝试。</div>
        <div v-for="item in history.slice().reverse()" :key="item.attempt.attempt_id" class="history-row">
          <span :class="['status', item.attempt.status]">{{ item.attempt.status }}</span>
          <span>{{ item.attempt.operation }}</span>
          <span>{{ new Date(item.attempt.started_at).toLocaleString() }}</span>
          <span>{{ item.result?.scoring_standard_version || '—' }}</span>
          <strong v-if="item.result">{{ item.result.total_score.toFixed(1) }}</strong>
          <span v-else class="error">{{ item.attempt.error_code }} {{ item.attempt.error_message }}</span>
        </div>
      </div>
    </template>
  </section>
</template>

<style scoped lang="scss">
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px; }
h3 { margin: 0 0 12px; font-size: 15px; color: #1f2937; }
.report-meta { display: flex; justify-content: space-between; gap: 10px; margin-bottom: 10px; color: #334155; code { color: #64748b; font-size: 11px; } }
.score-header { display: flex; align-items: center; gap: 16px; padding: 12px; border-radius: 8px; background: #eff6ff; .total b { color: #1d4ed8; font-size: 30px; } .total span { color: #64748b; } small { display: block; color: #64748b; margin-top: 4px; } }
.dimension-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 10px; article { border: 1px solid #e5e7eb; border-radius: 7px; padding: 9px; } header { display: flex; justify-content: space-between; color: #334155; } p { margin: 6px 0 0; color: #64748b; font-size: 12px; line-height: 1.5; } }
.conclusions { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; h4 { margin: 10px 0 4px; color: #334155; } ul { margin: 0; padding-left: 18px; color: #64748b; font-size: 12px; } }
.history { margin-top: 12px; border-top: 1px solid #e5e7eb; h4 { margin: 10px 0; } }
.history-row { display: grid; grid-template-columns: 75px 65px 145px 45px 50px 1fr; gap: 8px; align-items: center; padding: 6px 0; border-bottom: 1px solid #f1f5f9; color: #64748b; font-size: 11px; }
.status { border-radius: 999px; padding: 3px 7px; text-align: center; &.succeeded { color: #047857; background: #dcfce7; } &.failed { color: #b91c1c; background: #fee2e2; } &.running { color: #92400e; background: #fef3c7; } }
.error { color: #b91c1c; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.muted, .empty { color: #94a3b8; font-size: 12px; padding: 14px 0; }
@media (max-width: 1000px) { .dimension-grid, .conclusions { grid-template-columns: 1fr; } }
</style>
