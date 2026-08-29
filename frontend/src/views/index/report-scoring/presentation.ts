import type { ReportRecord, ScoreResult } from "@/api/report_scoring";

const statusLabels = {
  not_scored: "未评分",
  running: "评分中",
  succeeded: "最近评分成功",
  failed: "最近评分失败",
} as const;

const FINAL_ATTRIBUTION_REPORT_HEADING =
  /^\s{0,3}#{1,6}\s+(?:\*\*)?(?:Wazuh\s+)?攻击溯源调查报告(?:\*\*)?\s*$/imu;

const ATTRIBUTION_REPORT_PRESENTATION_NODES = new Set([
  "reply",
  "final_report",
  "Reporter_Node",
]);

export function hasFinalAttributionReportHeading(content: string): boolean {
  return FINAL_ATTRIBUTION_REPORT_HEADING.test(content);
}

export function isAttributionReportPresentationNode(node: unknown): boolean {
  return typeof node === "string" && ATTRIBUTION_REPORT_PRESENTATION_NODES.has(node);
}

export function isAttributionReportMessage(
  role: unknown,
  node: unknown,
  content: string,
): boolean {
  if (role !== "assistant" || !isAttributionReportPresentationNode(node)) return false;
  return node === "final_report" || hasFinalAttributionReportHeading(content);
}

export function buildReportActionKey(
  agentId: string,
  threadId: string,
  messageIndex: number,
): string {
  return JSON.stringify([agentId, threadId, messageIndex]);
}

export function getReportScorePresentation(
  report: ReportRecord,
  latestScore: ScoreResult | null | undefined,
) {
  const status = report.latest_attempt_status || "not_scored";
  return {
    scoreText: latestScore ? latestScore.total_score.toFixed(1) : null,
    status,
    statusText: statusLabels[status],
  };
}

export function isReportScoreBusy(
  report: Pick<ReportRecord, "report_id" | "latest_attempt_status">,
  busyReportIds: ReadonlySet<string>,
): boolean {
  return busyReportIds.has(report.report_id) || report.latest_attempt_status === "running";
}

export function formatReportScoringError(error: unknown): string {
  if (error instanceof Error) {
    const code =
      "code" in error && typeof error.code === "string" ? error.code : "REQUEST_FAILED";
    return `${code}: ${error.message}`;
  }
  return `REQUEST_FAILED: ${String(error)}`;
}

export function formatLocalReportSaved(filepath: string): string {
  return `报告已保存到：${filepath}`;
}

export function formatReportRegistrationSaved(filepath: string, reportId: string): string {
  return `报告已保存到：${filepath}；评分报告已登记：${reportId}`;
}

export function formatReportRegistrationPartialFailure(
  filepath: string,
  error: { code?: string; message?: string },
): string {
  const code = error.code || "SCORING_REGISTRATION_ERROR";
  const message = error.message || "评分登记失败";
  return `报告已保存到：${filepath}；评分登记失败（${code}）：${message}`;
}
