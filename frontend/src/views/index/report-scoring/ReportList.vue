<script setup lang="ts">
import type { ReportRecord, ScoreResult } from "@/api/report_scoring";
import { getReportScorePresentation } from "./presentation";

const props = defineProps<{
  reports: ReportRecord[];
  latestScores: Record<string, ScoreResult | null>;
  busyReportIds: Set<string>;
  selectedReportId?: string;
}>();

const emit = defineEmits<{
  select: [report: ReportRecord];
  score: [report: ReportRecord, rescore: boolean];
}>();

const sourceLabels: Record<string, string> = {
  ai_chat: "AI 对话",
  studio: "Studio",
  upload: "电脑上传",
};

const presentation = (report: ReportRecord) =>
  getReportScorePresentation(report, props.latestScores[report.report_id]);
</script>

<template>
  <section class="card list-card">
    <div class="card-title"><h3>已登记报告</h3><span>{{ reports.length }} 份</span></div>
    <div v-if="!reports.length" class="empty">当前筛选下没有报告。</div>
    <div v-else class="table-wrap">
      <table>
        <thead><tr><th>报告</th><th>智能体</th><th>来源</th><th>导入时间</th><th>最近评分</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="report in reports" :key="report.report_id" :class="{ selected: selectedReportId === report.report_id }" @click="emit('select', report)">
            <td><strong>{{ report.original_filename }}</strong><small>{{ report.report_sha256.slice(0, 10) }}…</small></td>
            <td>{{ report.agent_id }}</td>
            <td>{{ sourceLabels[report.source_type] }}</td>
            <td>{{ new Date(report.imported_at).toLocaleString() }}</td>
            <td>
              <div class="score-state">
                <span v-if="presentation(report).scoreText" class="score-pill">{{ presentation(report).scoreText }}</span>
                <span :class="['status-text', presentation(report).status]">{{ presentation(report).statusText }}</span>
              </div>
            </td>
            <td class="actions" @click.stop>
              <button v-if="!latestScores[report.report_id]" :disabled="busyReportIds.has(report.report_id)" @click="emit('score', report, false)">首次评分</button>
              <button v-else class="secondary" :disabled="busyReportIds.has(report.report_id)" @click="emit('score', report, true)">重新评分</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped lang="scss">
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px; }
.card-title { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; h3 { margin: 0; font-size: 15px; color: #1f2937; } span { color: #64748b; font-size: 12px; } }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { padding: 8px; text-align: left; color: #64748b; border-bottom: 1px solid #e5e7eb; white-space: nowrap; }
td { padding: 9px 8px; border-bottom: 1px solid #f1f5f9; color: #334155; }
tr { cursor: pointer; &:hover, &.selected { background: #eff6ff; } }
td strong, td small { display: block; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
td small, .muted { color: #94a3b8; margin-top: 3px; }
.status-text { color: #94a3b8; &.running { color: #92400e; } &.failed { color: #b91c1c; } }
.score-pill { display: inline-flex; min-width: 38px; justify-content: center; border-radius: 999px; padding: 4px 8px; background: #dcfce7; color: #047857; font-weight: 700; }
.score-state { display: flex; align-items: center; gap: 6px; white-space: nowrap; }
.actions { white-space: nowrap; }
button { border: 0; border-radius: 5px; padding: 6px 9px; background: #2563eb; color: #fff; cursor: pointer; &.secondary { background: #475569; } &:disabled { opacity: .45; cursor: not-allowed; } }
.empty { padding: 24px; text-align: center; color: #94a3b8; }
</style>
