<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import {
  getComparison,
  getReport,
  getLatestScore,
  getScoreHistory,
  listAgents,
  listReports,
  listTestCases,
  ReportScoringApiError,
  scoreReport,
  type AgentSummary,
  type ComparisonResponse,
  type ReportRecord,
  type ScoreHistoryItem,
  type ScoreResult,
  type TestCaseSummary,
} from "@/api/report_scoring";
import ComparisonTable from "./report-scoring/ComparisonTable.vue";
import ReportList from "./report-scoring/ReportList.vue";
import ReportRegistrationPanel from "./report-scoring/ReportRegistrationPanel.vue";
import ScoreDetail from "./report-scoring/ScoreDetail.vue";
import { formatReportScoringError, isReportScoreBusy } from "./report-scoring/presentation";

const cases = ref<TestCaseSummary[]>([]);
const agents = ref<AgentSummary[]>([]);
const selectedCaseId = ref("");
const selectedAgentId = ref("");
const reports = ref<ReportRecord[]>([]);
const latestScores = ref<Record<string, ScoreResult | null>>({});
const selectedReport = ref<ReportRecord | null>(null);
const selectedResult = ref<ScoreResult | null>(null);
const history = ref<ScoreHistoryItem[]>([]);
const comparison = ref<ComparisonResponse | null>(null);
const busyReportIds = ref(new Set<string>());
const loading = ref(false);
const errorMessage = ref("");
const SCORE_STATUS_POLL_INTERVAL_MS = 2_000;
let scoreStatusPollTimer: number | undefined;
let scoreStatusPollInFlight = false;

function showError(error: unknown) {
  errorMessage.value = formatReportScoringError(error);
}

async function loadCatalog() {
  try {
    [cases.value, agents.value] = await Promise.all([listTestCases(), listAgents()]);
    if (!selectedCaseId.value && cases.value.length) selectedCaseId.value = cases.value[0].test_case_id;
  } catch (error) {
    showError(error);
  }
}

async function loadReportDetails(report: ReportRecord) {
  selectedReport.value = report;
  try {
    history.value = await getScoreHistory(report.report_id);
    selectedResult.value = latestScores.value[report.report_id] || null;
  } catch (error) {
    showError(error);
  }
}

async function refresh(options: { clearError?: boolean } = {}) {
  if (!selectedCaseId.value) return;
  loading.value = true;
  if (options.clearError !== false) errorMessage.value = "";
  try {
    reports.value = await listReports({
      testCaseId: selectedCaseId.value,
      agentId: selectedAgentId.value || undefined,
    });
    const entries = await Promise.all(
      reports.value.map(async (report) => {
        try {
          return [report.report_id, await getLatestScore(report.report_id)] as const;
        } catch (error) {
          if (error instanceof ReportScoringApiError && error.code === "SCORING_ATTEMPT_NOT_FOUND") {
            return [report.report_id, null] as const;
          }
          throw error;
        }
      }),
    );
    latestScores.value = Object.fromEntries(entries);
    comparison.value = await getComparison(selectedCaseId.value);
    if (selectedReport.value) {
      const current = reports.value.find((item) => item.report_id === selectedReport.value?.report_id);
      if (current) await loadReportDetails(current);
      else {
        selectedReport.value = null;
        selectedResult.value = null;
        history.value = [];
      }
    }
  } catch (error) {
    showError(error);
  } finally {
    loading.value = false;
  }
}

async function pollRunningReportStatuses() {
  if (scoreStatusPollInFlight || loading.value) return;
  const runningReportIds = reports.value
    .filter((report) => report.latest_attempt_status === "running")
    .map((report) => report.report_id);
  if (!runningReportIds.length) return;

  scoreStatusPollInFlight = true;
  try {
    const updatedReports = await Promise.all(runningReportIds.map((reportId) => getReport(reportId)));
    const updatesById = new Map(updatedReports.map((report) => [report.report_id, report]));
    reports.value = reports.value.map((report) => updatesById.get(report.report_id) || report);
    if (updatedReports.some((report) => report.latest_attempt_status !== "running")) {
      await refresh({ clearError: false });
    }
  } catch (error) {
    showError(error);
  } finally {
    scoreStatusPollInFlight = false;
  }
}

async function runScore(report: ReportRecord, rescore: boolean) {
  if (isReportScoreBusy(report, busyReportIds.value)) return;
  if (rescore && !window.confirm("重新评分会调用模型并新增历史记录，旧结果不会被覆盖。是否继续？")) return;
  const nextBusy = new Set(busyReportIds.value);
  nextBusy.add(report.report_id);
  busyReportIds.value = nextBusy;
  errorMessage.value = "";
  try {
    await scoreReport(report.report_id, rescore);
    await refresh();
    await loadReportDetails(report);
  } catch (error) {
    const operationError = formatReportScoringError(error);
    await refresh({ clearError: false });
    errorMessage.value = operationError;
  } finally {
    const done = new Set(busyReportIds.value);
    done.delete(report.report_id);
    busyReportIds.value = done;
  }
}

watch([selectedCaseId, selectedAgentId], () => refresh());
onMounted(async () => {
  await loadCatalog();
  await refresh();
  scoreStatusPollTimer = window.setInterval(
    () => void pollRunningReportStatuses(),
    SCORE_STATUS_POLL_INTERVAL_MS,
  );
});
onBeforeUnmount(() => {
  if (scoreStatusPollTimer !== undefined) window.clearInterval(scoreStatusPollTimer);
});
</script>

<template>
  <div class="report-scoring-page">
    <header class="page-header">
      <div><h2>报告评分</h2><p>开发期工具 · 最终报告是唯一被评分产物</p></div>
      <div class="filters">
        <label>案例<select v-model="selectedCaseId"><option v-for="item in cases" :key="item.test_case_id" :value="item.test_case_id">{{ item.display_name }} · {{ item.scoring_standard_version }}</option></select></label>
        <label>智能体<select v-model="selectedAgentId"><option value="">全部智能体</option><option v-for="item in agents" :key="item.agent_id" :value="item.agent_id">{{ item.display_name }}</option></select></label>
        <button :disabled="loading" @click="refresh()">{{ loading ? "刷新中…" : "刷新" }}</button>
      </div>
    </header>

    <div v-if="errorMessage" class="page-error">{{ errorMessage }}</div>
    <ReportRegistrationPanel :cases="cases" :agents="agents" @registered="refresh()" />
    <ReportList
      :reports="reports"
      :latest-scores="latestScores"
      :busy-report-ids="busyReportIds"
      :selected-report-id="selectedReport?.report_id"
      @select="loadReportDetails"
      @score="runScore"
    />
    <div class="lower-grid">
      <ScoreDetail :report="selectedReport" :result="selectedResult" :history="history" />
      <ComparisonTable :comparison="comparison" />
    </div>
  </div>
</template>

<style scoped lang="scss">
.report-scoring-page { height: 100%; overflow-y: auto; padding: 16px; box-sizing: border-box; display: flex; flex-direction: column; gap: 12px; background: #f8fafc; }
.page-header { display: flex; justify-content: space-between; gap: 20px; align-items: center; h2 { margin: 0; color: #1e3a8a; font-size: 21px; } p { margin: 4px 0 0; color: #64748b; font-size: 12px; } }
.filters { display: flex; align-items: flex-end; gap: 10px; label { display: flex; flex-direction: column; gap: 4px; color: #64748b; font-size: 11px; } select { min-width: 190px; padding: 7px 9px; border: 1px solid #d1d5db; border-radius: 6px; background: #fff; } button { padding: 8px 13px; border: 0; border-radius: 6px; background: #2563eb; color: #fff; cursor: pointer; &:disabled { opacity: .5; } } }
.page-error { border: 1px solid #fecaca; border-radius: 7px; padding: 9px 12px; background: #fef2f2; color: #b91c1c; font-size: 12px; }
.lower-grid { display: grid; grid-template-columns: minmax(420px, 1fr) minmax(560px, 1.35fr); gap: 12px; align-items: start; }
@media (max-width: 1200px) { .page-header { align-items: flex-start; flex-direction: column; } .lower-grid { grid-template-columns: 1fr; } }
</style>
