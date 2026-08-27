const API_ROOT = "http://127.0.0.1:8001/api/report-scoring";

export interface TestCaseSummary {
  test_case_id: string;
  display_name: string;
  scoring_standard_version: string;
  input_sha256: string;
}

export interface AgentSummary {
  agent_id: string;
  display_name: string;
}

export type ReportSource = "ai_chat" | "studio" | "upload" | "local_import";

export interface ReportRecord {
  report_id: string;
  test_case_id: string;
  agent_id: string;
  source_type: ReportSource;
  original_filename: string;
  stored_path: string;
  report_sha256: string;
  input_sha256: string;
  imported_at: string;
  thread_id?: string | null;
  run_id?: string | null;
  note?: string | null;
  attack_run_id?: string | null;
  anchor_sha256?: string | null;
  confirmation_actor?: string | null;
  confirmed_at?: string | null;
  latest_attempt_status?: "not_scored" | "running" | "succeeded" | "failed";
  latest_attempt_id?: string | null;
  latest_score_id?: string | null;
  latest_total_score?: number | null;
}

export interface ReportScoringErrorPayload {
  code: string;
  message: string;
  field?: string;
  details?: Record<string, unknown>;
}

export type ChatReportRegistrationResult =
  | { status: "ok"; report: ReportRecord }
  | { status: "error"; error: ReportScoringErrorPayload };

export interface ChatReportSaveResponse {
  status: "ok";
  filepath: string;
  filename: string;
  message: string;
  scoring_registration?: ChatReportRegistrationResult;
}

export interface ChatReportSavePayload {
  content: string;
  filename?: string;
  scoring_registration?: {
    test_case_id: string;
    agent_id: string;
    thread_id?: string;
    run_id?: string;
    note?: string;
  };
}

export interface DimensionScore {
  score: number;
  reason: string;
  report_evidence: string[];
  [key: string]: unknown;
}

export const REPORT_SCORE_DIMENSIONS = [
  { key: "anchor_accuracy", label: "初始事件识别准确性", maximum: 10 },
  { key: "evidence_recall", label: "关键证据检索与覆盖度", maximum: 20 },
  { key: "timeline", label: "事件时间线准确性", maximum: 5 },
  { key: "process_chain", label: "攻击链重建与因果分析", maximum: 20 },
  { key: "mitre_mapping", label: "MITRE ATT&CK 映射质量", maximum: 30 },
  { key: "negative_findings", label: "未发生行为核验", maximum: 15 },
] as const;

export type ReportScoreDimensionKey = (typeof REPORT_SCORE_DIMENSIONS)[number]["key"];

export interface ScoreCandidate {
  anchor_accuracy: DimensionScore;
  evidence_recall: DimensionScore;
  timeline: DimensionScore;
  process_chain: DimensionScore;
  mitre_mapping: DimensionScore;
  negative_findings: DimensionScore;
  root_causes: Array<Record<string, unknown>>;
  strengths: string[];
  major_issues: string[];
  model_total?: number | null;
}

export interface ScoreResult {
  score_id: string;
  attempt_id: string;
  report_id: string;
  test_case_id: string;
  agent_id: string;
  scoring_standard_version: string;
  model_name: string;
  scoring_agent_version: string;
  prompt_version: string;
  scoring_contract_version?: string | null;
  scoring_context_sha256?: string | null;
  completed_at: string;
  total_score: number;
  score: ScoreCandidate;
}

export interface ScoringAttempt {
  attempt_id: string;
  request_id: string;
  report_id: string;
  operation: "score" | "rescore";
  scoring_contract_version?: string | null;
  status: "running" | "succeeded" | "failed";
  started_at: string;
  completed_at?: string | null;
  score_id?: string | null;
  error_code?: string | null;
  error_message?: string | null;
}

export interface ScoreHistoryItem {
  attempt: ScoringAttempt;
  result?: ScoreResult | null;
}

export interface ComparisonAgent {
  agent_id: string;
  display_name: string;
  registered_report_count: number;
  successfully_scored_report_count: number;
  report_scores: Array<{ report_id: string; score_id: string; total_score: number }>;
  average_total: number | null;
  minimum_total: number | null;
  maximum_total: number | null;
  dimension_averages: Record<ReportScoreDimensionKey, number | null>;
}

export interface ComparisonResponse {
  test_case_id: string;
  scoring_standard_version: string;
  agents: ComparisonAgent[];
}

export class ReportScoringApiError extends Error {
  code: string;
  status: number;
  details?: Record<string, unknown>;

  constructor(status: number, payload: any) {
    super(payload?.message || `请求失败 (${status})`);
    this.name = "ReportScoringApiError";
    this.code = payload?.code || "REQUEST_FAILED";
    this.status = status;
    this.details = payload?.details;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_ROOT}${path}`, init);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new ReportScoringApiError(response.status, payload);
  }
  return payload as T;
}

export const listTestCases = () => request<TestCaseSummary[]>("/test-cases");
export const listAgents = () => request<AgentSummary[]>("/agents");

export async function listReports(filters: {
  testCaseId?: string;
  agentId?: string;
  sourceType?: ReportSource;
}): Promise<ReportRecord[]> {
  const params = new URLSearchParams();
  if (filters.testCaseId) params.set("test_case_id", filters.testCaseId);
  if (filters.agentId) params.set("agent_id", filters.agentId);
  if (filters.sourceType) params.set("source_type", filters.sourceType);
  params.set("limit", "200");
  const response = await request<{ items: ReportRecord[] }>(`/reports?${params.toString()}`);
  return response.items;
}

export function uploadReport(form: FormData) {
  return request<ReportRecord>("/reports/upload", { method: "POST", body: form });
}

export function scoreReport(reportId: string, rescore = false) {
  return request<{ attempt: ScoringAttempt; result: ScoreResult; reused: boolean }>(
    `/reports/${encodeURIComponent(reportId)}/${rescore ? "rescore" : "score"}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ request_id: crypto.randomUUID() }),
    },
  );
}

export const getScoreHistory = (reportId: string) =>
  request<ScoreHistoryItem[]>(`/reports/${encodeURIComponent(reportId)}/scores`);

export const getLatestScore = (reportId: string) =>
  request<ScoreResult>(`/reports/${encodeURIComponent(reportId)}/scores/latest`);

export const getComparison = (testCaseId: string, standardVersion = "v3.0") =>
  request<ComparisonResponse>(
    `/comparisons?test_case_id=${encodeURIComponent(testCaseId)}&standard_version=${encodeURIComponent(standardVersion)}`,
  );

export async function saveChatReport(
  payload: ChatReportSavePayload,
): Promise<ChatReportSaveResponse> {
  const response = await fetch("http://127.0.0.1:8001/api/report/save", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || result.status !== "ok") {
    throw new ReportScoringApiError(response.status, result);
  }
  return result as ChatReportSaveResponse;
}

export const saveAndRegisterChatReport = saveChatReport;
