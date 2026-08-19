import type { ReportRecord, ScoreResult } from "@/api/report_scoring";

const statusLabels = {
  not_scored: "未评分",
  running: "评分中",
  succeeded: "最近评分成功",
  failed: "最近评分失败",
} as const;

const FINAL_ATTRIBUTION_REPORT_HEADING =
  /^\s{0,3}#{1,6}\s+(?:\*\*)?(?:Wazuh\s+)?攻击溯源调查报告(?:\*\*)?\s*$/imu;

export function hasFinalAttributionReportHeading(content: string): boolean {
  return FINAL_ATTRIBUTION_REPORT_HEADING.test(content);
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

export function formatReportScoringError(error: unknown): string {
  if (error instanceof Error) {
    const code =
      "code" in error && typeof error.code === "string" ? error.code : "REQUEST_FAILED";
    return `${code}: ${error.message}`;
  }
  return `REQUEST_FAILED: ${String(error)}`;
}
