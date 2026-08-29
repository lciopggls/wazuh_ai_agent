import assert from "node:assert/strict";
import test from "node:test";

import { REPORT_SCORE_DIMENSIONS } from "../src/api/report_scoring.ts";
import {
  buildReportActionKey,
  formatLocalReportSaved,
  formatReportRegistrationPartialFailure,
  formatReportRegistrationSaved,
  formatReportScoringError,
  getReportScorePresentation,
  hasFinalAttributionReportHeading,
  isAttributionReportMessage,
  isAttributionReportPresentationNode,
  isReportScoreBusy,
} from "../src/views/index/report-scoring/presentation.ts";

const report = (status) => ({ latest_attempt_status: status });
const score = { total_score: 90 };

test("六维度正式名称和权重使用统一映射", () => {
  assert.deepEqual(
    REPORT_SCORE_DIMENSIONS.map(({ key, label, maximum }) => [key, label, maximum]),
    [
      ["anchor_accuracy", "初始事件识别准确性", 10],
      ["evidence_recall", "关键证据检索与覆盖度", 20],
      ["timeline", "事件时间线准确性", 5],
      ["process_chain", "攻击链重建与因果分析", 20],
      ["mitre_mapping", "MITRE ATT&CK 映射质量", 30],
      ["negative_findings", "未发生行为核验", 15],
    ],
  );
});

test("首次评分失败时显示失败且没有伪造分数", () => {
  assert.deepEqual(getReportScorePresentation(report("failed"), null), {
    scoreText: null,
    status: "failed",
    statusText: "最近评分失败",
  });
});

test("旧成功分数与最近重评分失败同时显示", () => {
  assert.deepEqual(getReportScorePresentation(report("failed"), score), {
    scoreText: "90.0",
    status: "failed",
    statusText: "最近评分失败",
  });
});

test("409 进行中错误保留 code 和 message", () => {
  const error = Object.assign(new Error("该报告已有评分正在进行"), {
    code: "SCORING_IN_PROGRESS",
  });
  assert.equal(
    formatReportScoringError(error),
    "SCORING_IN_PROGRESS: 该报告已有评分正在进行",
  );
});

test("服务端或本地任一状态显示评分中时禁止重复评分", () => {
  assert.equal(
    isReportScoreBusy({ report_id: "rpt_running", latest_attempt_status: "running" }, new Set()),
    true,
  );
  assert.equal(
    isReportScoreBusy(
      { report_id: "rpt_local", latest_attempt_status: "not_scored" },
      new Set(["rpt_local"]),
    ),
    true,
  );
  assert.equal(
    isReportScoreBusy({ report_id: "rpt_done", latest_attempt_status: "succeeded" }, new Set()),
    false,
  );
});

test("只有带报告标题的最终回复才允许保存并登记", () => {
  assert.equal(
    hasFinalAttributionReportHeading("### **攻击溯源调查报告**\n\n正文"),
    true,
  );
  assert.equal(
    hasFinalAttributionReportHeading("# Wazuh 攻击溯源调查报告\n\n正文"),
    true,
  );
  assert.equal(
    hasFinalAttributionReportHeading("请启动攻击溯源调查。请问线索是否符合要求？"),
    false,
  );
});

test("攻击溯源 Reporter_Node 报告可显示保存和评分操作", () => {
  const reportContent = "# 攻击溯源调查报告\n\n正文";

  assert.equal(isAttributionReportPresentationNode("Reporter_Node"), true);
  assert.equal(isAttributionReportMessage("assistant", "Reporter_Node", reportContent), true);
  assert.equal(
    isAttributionReportMessage("assistant", "Reporter_Node", "报告生成失败，请稍后重试"),
    false,
  );
});

test("非报告节点即使包含报告标题也不显示保存操作", () => {
  assert.equal(
    isAttributionReportMessage("assistant", "model", "# 攻击溯源调查报告\n\n正文"),
    false,
  );
  assert.equal(isAttributionReportMessage("user", "Reporter_Node", "# 攻击溯源调查报告"), false);
});

test("不同智能体相同消息序号使用独立报告操作状态", () => {
  const simpleKey = buildReportActionKey("baseline_agent_simple", "tid_simple", 7);
  const plusKey = buildReportActionKey("baseline_agent_plus", "tid_plus", 7);

  assert.notEqual(simpleKey, plusKey);
  assert.equal(simpleKey, buildReportActionKey("baseline_agent_simple", "tid_simple", 7));
});

test("报告保存和登记反馈包含实际路径与报告 ID", () => {
  assert.equal(
    formatLocalReportSaved("D:\\reports\\trace.md"),
    "报告已保存到：D:\\reports\\trace.md",
  );
  assert.equal(
    formatReportRegistrationSaved("D:\\reports\\trace.md", "rpt_123"),
    "报告已保存到：D:\\reports\\trace.md；评分报告已登记：rpt_123",
  );
});

test("评分登记失败反馈仍保留本地保存路径", () => {
  assert.equal(
    formatReportRegistrationPartialFailure("D:\\reports\\trace.md", {
      code: "INVALID_TEST_CASE",
      message: "测试案例不存在",
    }),
    "报告已保存到：D:\\reports\\trace.md；评分登记失败（INVALID_TEST_CASE）：测试案例不存在",
  );
});
