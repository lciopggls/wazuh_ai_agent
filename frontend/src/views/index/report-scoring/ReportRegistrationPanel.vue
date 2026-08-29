<script setup lang="ts">
import { computed, ref, watchEffect } from "vue";
import {
  importStudioReport,
  type AgentSummary,
  type TestCaseSummary,
  uploadReport,
} from "@/api/report_scoring";

const props = defineProps<{ cases: TestCaseSummary[]; agents: AgentSummary[] }>();
const emit = defineEmits<{ registered: [] }>();

const testCaseId = ref("");
const agentId = ref("");
const studioPath = ref("");
const selectedFile = ref<File | null>(null);
const threadId = ref("");
const runId = ref("");
const note = ref("");
const busy = ref(false);
const errorMessage = ref("");
const successMessage = ref("");
const canSubmit = computed(() => Boolean(testCaseId.value && agentId.value));

watchEffect(() => {
  if (!testCaseId.value && props.cases.length) testCaseId.value = props.cases[0].test_case_id;
  if (!agentId.value && props.agents.length) agentId.value = props.agents[0].agent_id;
});

function optionalFields() {
  return {
    ...(threadId.value.trim() ? { thread_id: threadId.value.trim() } : {}),
    ...(runId.value.trim() ? { run_id: runId.value.trim() } : {}),
    ...(note.value.trim() ? { note: note.value.trim() } : {}),
  };
}

function displayError(error: any) {
  errorMessage.value = `${error?.code || "REQUEST_FAILED"}: ${error?.message || String(error)}`;
  successMessage.value = "";
}

async function submitUpload() {
  if (!canSubmit.value || !selectedFile.value) return;
  busy.value = true;
  errorMessage.value = "";
  try {
    const form = new FormData();
    form.append("file", selectedFile.value);
    form.append("test_case_id", testCaseId.value);
    form.append("agent_id", agentId.value);
    for (const [key, value] of Object.entries(optionalFields())) form.append(key, value);
    await uploadReport(form);
    successMessage.value = "手动报告已登记。";
    selectedFile.value = null;
    emit("registered");
  } catch (error) {
    displayError(error);
  } finally {
    busy.value = false;
  }
}

async function submitStudio() {
  if (!canSubmit.value || !studioPath.value.trim()) return;
  busy.value = true;
  errorMessage.value = "";
  try {
    await importStudioReport({
      relative_path: studioPath.value.trim(),
      test_case_id: testCaseId.value,
      agent_id: agentId.value,
      ...optionalFields(),
    });
    successMessage.value = "Studio 报告已登记。";
    studioPath.value = "";
    emit("registered");
  } catch (error) {
    displayError(error);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <section class="card registration-card">
    <h3>登记报告</h3>
    <div class="form-grid">
      <label>测试案例<select v-model="testCaseId"><option v-for="item in cases" :key="item.test_case_id" :value="item.test_case_id">{{ item.display_name }}</option></select></label>
      <label>被测智能体<select v-model="agentId"><option v-for="item in agents" :key="item.agent_id" :value="item.agent_id">{{ item.display_name }}</option></select></label>
      <label>Thread ID（可选）<input v-model="threadId" maxlength="160" /></label>
      <label>Run ID（可选）<input v-model="runId" maxlength="160" /></label>
      <label class="wide">备注（可选）<input v-model="note" maxlength="1000" /></label>
    </div>
    <div class="source-row">
      <div class="source-box">
        <strong>电脑上传</strong>
        <input type="file" accept=".md,.txt,text/markdown,text/plain" @change="selectedFile = ($event.target as HTMLInputElement).files?.[0] || null" />
        <button :disabled="busy || !canSubmit || !selectedFile" @click="submitUpload">上传并登记</button>
      </div>
      <div class="source-box">
        <strong>Studio inbox</strong>
        <input v-model="studioPath" placeholder="例如 SIM-204-report.md" />
        <button :disabled="busy || !canSubmit || !studioPath.trim()" @click="submitStudio">从受控目录登记</button>
      </div>
    </div>
    <p v-if="successMessage" class="success">{{ successMessage }}</p>
    <p v-if="errorMessage" class="error">{{ errorMessage }}</p>
  </section>
</template>

<style scoped lang="scss">
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px; }
h3 { margin: 0 0 12px; color: #1f2937; font-size: 15px; }
.form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
label { display: flex; flex-direction: column; gap: 5px; color: #64748b; font-size: 12px; }
.wide { grid-column: 1 / -1; }
input, select { min-width: 0; border: 1px solid #d1d5db; border-radius: 6px; padding: 7px 9px; background: #fff; color: #1f2937; }
.source-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 12px; }
.source-box { display: grid; grid-template-columns: auto 1fr auto; align-items: center; gap: 8px; padding: 10px; background: #f8fafc; border-radius: 8px; color: #334155; font-size: 12px; }
button { border: 0; border-radius: 6px; padding: 8px 12px; color: #fff; background: #2563eb; cursor: pointer; &:disabled { opacity: .45; cursor: not-allowed; } }
.success { color: #059669; margin: 10px 0 0; }
.error { color: #dc2626; margin: 10px 0 0; word-break: break-word; }
@media (max-width: 1000px) { .source-row, .form-grid { grid-template-columns: 1fr; } .wide { grid-column: auto; } .source-box { grid-template-columns: 1fr; } }
</style>
