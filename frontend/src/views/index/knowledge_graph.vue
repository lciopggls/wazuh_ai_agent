<template>
  <div class="kg-container">
    <!-- 顶部操作栏 -->
    <div class="kg-toolbar">
      <button class="kg-btn kg-btn--primary" @click="showGallery">
        🖼️ 图谱展示
      </button>

      <div class="kg-upload-group">
        <input
          ref="fileInputRef"
          type="file"
          accept=".txt,.pdf,.md"
          style="display: none"
          @change="onFileSelected"
        />
        <input
          v-model="uploadFileName"
          class="kg-input"
          type="text"
          placeholder="未选择文件（支持 txt / pdf / md）"
          readonly
          @click="triggerFilePicker"
        />
        <button class="kg-btn kg-btn--upload" @click="triggerFilePicker">
          📤 上传文件
        </button>
      </div>

      <button
        class="kg-btn kg-btn--generate"
        :disabled="generating"
        @click="generateGraph"
      >
        {{ generating ? '⏳ 生成中...' : '⚡ 生成图谱' }}
      </button>

      <button
        class="kg-btn kg-btn--save"
        :disabled="!selectedOutputFile || savingToGallery"
        @click="saveToGallery"
      >
        {{ savingToGallery ? '⏳ 存入中...' : '💾 存入图谱' }}
      </button>
    </div>

    <!-- 状态信息 -->
    <div v-if="statusMessage" class="kg-status" :class="statusType">
      {{ statusMessage }}
    </div>

    <!-- 主内容区 -->
    <div class="kg-body">
      <!-- Gallery 展示 -->
      <div v-if="activeView === 'gallery'" class="kg-panel">
        <div class="kg-panel-header">
          <h3>🖼️ 图谱展示（Gallery）</h3>
          <button class="kg-btn kg-btn--sm kg-btn--refresh" @click="loadGallery">🔄 刷新</button>
        </div>
        <div v-if="galleryFiles.length === 0" class="kg-empty">
          暂无图谱文件，请先生成或存入图谱。
        </div>
        <div v-else class="kg-file-grid">
          <div
            v-for="file in galleryFiles"
            :key="file.name"
            :class="['kg-file-card', previewFile?.name === file.name ? 'kg-file-card--active' : '']"
            @click="previewGalleryFile(file)"
          >
            <span class="kg-file-icon">📄</span>
            <span class="kg-file-name">{{ file.name }}</span>
            <span class="kg-file-size">{{ (file.size / 1024).toFixed(1) }} KB</span>
            <button
              class="kg-btn-delete"
              title="删除"
              @click.stop="deleteGalleryFile(file)"
            >✕</button>
          </div>
        </div>
      </div>

      <!-- Output 展示 -->
      <div v-if="activeView === 'output'" class="kg-panel">
        <div class="kg-panel-header">
          <h3>⚡ 生成的图谱（Output）</h3>
          <button class="kg-btn kg-btn--sm kg-btn--refresh" @click="loadOutput">🔄 刷新</button>
        </div>
        <div v-if="outputFiles.length === 0" class="kg-empty">
          尚无生成的图谱，请先上传文件并点击"生成图谱"。
        </div>
        <div v-else class="kg-file-grid">
          <div
            v-for="file in outputFiles"
            :key="file.name"
            :class="[
              'kg-file-card',
              previewFile?.name === file.name ? 'kg-file-card--active' : '',
              selectedOutputFile === file.name ? 'kg-file-card--selected' : '',
            ]"
            @click="selectOutputFile(file)"
          >
            <span class="kg-file-icon">📄</span>
            <span class="kg-file-name">{{ file.name }}</span>
            <span class="kg-file-size">{{ (file.size / 1024).toFixed(1) }} KB</span>
            <span v-if="selectedOutputFile === file.name" class="kg-file-check">✓ 已选</span>
          </div>
        </div>
      </div>

      <!-- HTML 预览 -->
      <div v-if="previewHtml" class="kg-preview">
        <div class="kg-preview-header">
          <h3>📖 预览：{{ previewFileName }}</h3>
          <button class="kg-btn kg-btn--sm kg-btn--close" @click="closePreview">✕ 关闭</button>
        </div>
        <div class="kg-preview-body">
          <iframe :srcdoc="previewHtml" class="kg-iframe" sandbox="allow-scripts allow-same-origin"></iframe>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";

// ── API 基址 ──
const API_BASE = "http://127.0.0.1:8001";

// ── 状态 ──
const fileInputRef = ref<HTMLInputElement | null>(null);
const uploadFileName = ref("");
const selectedFile = ref<File | null>(null);

const activeView = ref<"gallery" | "output">("gallery");

const galleryFiles = ref<any[]>([]);
const outputFiles = ref<any[]>([]);

const previewFile = ref<{ name: string } | null>(null);
const previewFileName = ref("");
const previewHtml = ref("");

const selectedOutputFile = ref("");

const statusMessage = ref("");
const statusType = ref<"info" | "success" | "error">("info");
const generating = ref(false);
const savingToGallery = ref(false);

// ── 工具 ──
function showStatus(msg: string, type: "info" | "success" | "error" = "info") {
  statusMessage.value = msg;
  statusType.value = type;
  setTimeout(() => {
    if (statusMessage.value === msg) statusMessage.value = "";
  }, 6000);
}

// ── 文件上传 ──
function triggerFilePicker() {
  fileInputRef.value?.click();
}

function onFileSelected(event: Event) {
  const input = event.target as HTMLInputElement;
  if (!input.files || input.files.length === 0) return;

  const file = input.files[0];
  const ext = "." + file.name.split(".").pop()?.toLowerCase();
  const allowed = [".txt", ".pdf", ".md"];

  if (!allowed.includes(ext)) {
    showStatus("不支持的文件格式，仅支持 txt / pdf / md", "error");
    input.value = "";
    return;
  }

  selectedFile.value = file;
  uploadFileName.value = file.name;
  showStatus(`已选择文件: ${file.name}`, "info");
}

async function uploadFile(): Promise<string | null> {
  if (!selectedFile.value) {
    showStatus("请先选择要上传的文件", "error");
    return null;
  }

  const formData = new FormData();
  formData.append("file", selectedFile.value);

  try {
    const res = await fetch(`${API_BASE}/api/knowledge-graph/upload`, {
      method: "POST",
      body: formData,
    });
    const data = await res.json();
    if (data.status === "ok") {
      showStatus(`文件 ${data.filename} 上传成功`, "success");
      return data.filename;
    } else {
      showStatus(`上传失败: ${data.detail || data.message}`, "error");
      return null;
    }
  } catch (err: any) {
    showStatus(`上传出错: ${err.message}`, "error");
    return null;
  }
}

// ── 图谱展示 ──
async function showGallery() {
  activeView.value = "gallery";
  previewHtml.value = "";
  previewFile.value = null;
  await loadGallery();
}

async function loadGallery() {
  try {
    const res = await fetch(`${API_BASE}/api/knowledge-graph/gallery`);
    const data = await res.json();
    if (data.status === "ok") {
      galleryFiles.value = data.files;
    }
  } catch (err: any) {
    showStatus(`获取 gallery 列表失败: ${err.message}`, "error");
  }
}

async function previewGalleryFile(file: any) {
  previewFile.value = file;
  previewFileName.value = file.name;
  previewHtml.value = "";
  try {
    const res = await fetch(`${API_BASE}/api/knowledge-graph/gallery/${encodeURIComponent(file.name)}`);
    const data = await res.json();
    if (data.status === "ok") {
      previewHtml.value = data.content;
    } else {
      showStatus("加载图谱文件失败", "error");
    }
  } catch (err: any) {
    showStatus(`预览出错: ${err.message}`, "error");
  }
}

// ── 生成图谱 ──
async function generateGraph() {
  // 如果没有上传文件，先尝试上传
  if (selectedFile.value) {
    const uploaded = await uploadFile();
    if (!uploaded) return;
  }

  generating.value = true;
  showStatus("正在生成图谱，请稍候...", "info");

  try {
    const res = await fetch(`${API_BASE}/api/knowledge-graph/generate`, {
      method: "POST",
    });
    const data = await res.json();

    if (data.status === "ok") {
      showStatus(data.message || "图谱生成完成", "success");
      activeView.value = "output";
      previewFile.value = null;
      previewHtml.value = "";
      await loadOutput();
      // 自动选中第一个输出文件
      if (outputFiles.value.length > 0) {
        selectedOutputFile.value = outputFiles.value[0].name;
      }
    } else {
      showStatus(`生成失败: ${data.message}`, "error");
      if (data.stderr) console.error("AttacKG stderr:", data.stderr);
    }
  } catch (err: any) {
    showStatus(`生成出错: ${err.message}`, "error");
  } finally {
    generating.value = false;
  }
}

// ── Output 操作 ──
async function loadOutput() {
  try {
    const res = await fetch(`${API_BASE}/api/knowledge-graph/output`);
    const data = await res.json();
    if (data.status === "ok") {
      outputFiles.value = data.files;
    }
  } catch (err: any) {
    showStatus(`获取 output 列表失败: ${err.message}`, "error");
  }
}

function selectOutputFile(file: any) {
  selectedOutputFile.value = file.name;
  // 同时预览
  previewFile.value = file;
  previewFileName.value = file.name;
  previewHtml.value = "";
  loadOutputPreview(file.name);
}

async function loadOutputPreview(filename: string) {
  try {
    const res = await fetch(`${API_BASE}/api/knowledge-graph/output/${encodeURIComponent(filename)}`);
    const data = await res.json();
    if (data.status === "ok") {
      previewHtml.value = data.content;
    } else {
      showStatus("加载输出文件失败", "error");
    }
  } catch (err: any) {
    showStatus(`预览出错: ${err.message}`, "error");
  }
}

// ── 存入图谱 ──
async function saveToGallery() {
  if (!selectedOutputFile.value) {
    showStatus("请先选择要存入图谱的文件", "error");
    return;
  }

  savingToGallery.value = true;
  try {
    const res = await fetch(`${API_BASE}/api/knowledge-graph/save-to-gallery`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename: selectedOutputFile.value }),
    });
    const data = await res.json();
    if (data.status === "ok") {
      showStatus(`图谱 ${data.filename} 已成功存入 gallery`, "success");
    } else {
      showStatus(`存入失败: ${data.detail || data.message}`, "error");
    }
  } catch (err: any) {
    showStatus(`存入出错: ${err.message}`, "error");
  } finally {
    savingToGallery.value = false;
  }
}

// ── 删除 Gallery 文件 ──
async function deleteGalleryFile(file: any) {
  if (!confirm(`确定要删除图谱「${file.name}」吗？此操作不可恢复。`)) return;

  // 如果当前预览的正是这个文件，关闭预览
  if (previewFile?.value?.name === file.name) {
    closePreview();
  }

  try {
    const res = await fetch(`${API_BASE}/api/knowledge-graph/gallery/${encodeURIComponent(file.name)}`, {
      method: "DELETE",
    });
    const data = await res.json();
    if (data.status === "ok") {
      showStatus(`图谱 ${file.name} 已删除`, "success");
      await loadGallery();
    } else {
      showStatus(`删除失败: ${data.detail || data.message}`, "error");
    }
  } catch (err: any) {
    showStatus(`删除出错: ${err.message}`, "error");
  }
}

// ── 关闭预览 ──
function closePreview() {
  previewHtml.value = "";
  previewFile.value = null;
  previewFileName.value = "";
}
</script>

<style scoped lang="scss">
.kg-container {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: #ffffff;
  border-radius: 8px;
  padding: 16px;
  overflow: hidden;
}

// ── 顶部操作栏 ──
.kg-toolbar {
  display: flex;
  align-items: center;
  gap: 10px;
  padding-bottom: 12px;
  border-bottom: 1px solid #e5e7eb;
  margin-bottom: 12px;
  flex-wrap: wrap;
}

.kg-btn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 7px 16px;
  font-size: 13px;
  font-weight: 600;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s ease;
  white-space: nowrap;
  background: #ffffff;
  color: #374151;

  &:hover:not(:disabled) {
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.08);
    transform: translateY(-1px);
  }

  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  &--primary {
    background: #1d4ed8;
    color: #fff;
    border-color: #1d4ed8;
    &:hover:not(:disabled) { background: #2563eb; }
  }

  &--upload {
    background: #059669;
    color: #fff;
    border-color: #059669;
    &:hover:not(:disabled) { background: #10b981; }
  }

  &--generate {
    background: #d97706;
    color: #fff;
    border-color: #d97706;
    &:hover:not(:disabled) { background: #f59e0b; }
  }

  &--save {
    background: #7c3aed;
    color: #fff;
    border-color: #7c3aed;
    &:hover:not(:disabled) { background: #8b5cf6; }
  }

  &--sm {
    padding: 4px 10px;
    font-size: 12px;
  }

  &--refresh {
    background: #f3f4f6;
    border-color: #d1d5db;
    color: #374151;
    &:hover { background: #e5e7eb; }
  }

  &--close {
    background: transparent;
    border-color: #ef4444;
    color: #ef4444;
    &:hover { background: #fef2f2; }
  }
}

.kg-upload-group {
  display: flex;
  align-items: center;
  gap: 6px;
  flex: 1;
  min-width: 200px;
  max-width: 420px;
}

.kg-input {
  flex: 1;
  padding: 7px 10px;
  font-size: 12px;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  background: #f9fafb;
  color: #6b7280;
  cursor: pointer;
  outline: none;
  &:hover { border-color: #9ca3af; }
}

// ── 状态信息 ──
.kg-status {
  padding: 8px 14px;
  border-radius: 6px;
  font-size: 13px;
  margin-bottom: 12px;
  animation: fadeIn 0.25s ease;

  &.info {
    background: #eff6ff;
    color: #1d4ed8;
    border: 1px solid #bfdbfe;
  }

  &.success {
    background: #f0fdf4;
    color: #166534;
    border: 1px solid #bbf7d0;
  }

  &.error {
    background: #fef2f2;
    color: #991b1b;
    border: 1px solid #fecaca;
  }
}

// ── 主体 ──
.kg-body {
  flex: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 12px;

  &::-webkit-scrollbar { width: 4px; }
  &::-webkit-scrollbar-thumb { background: #31ABE3; border-radius: 2px; }
}

// ── 面板 ──
.kg-panel {
  flex-shrink: 0;
}

.kg-panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;

  h3 {
    margin: 0;
    font-size: 14px;
    font-weight: 600;
    color: #374151;
  }
}

.kg-empty {
  text-align: center;
  padding: 40px 0;
  color: #9ca3af;
  font-size: 13px;
}

// ── 文件网格 ──
.kg-file-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 8px;
}

.kg-file-card {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px;
  border: 1px solid #e5e7eb;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s ease;
  background: #ffffff;

  &:hover {
    border-color: #31ABE3;
    background: #f0f7ff;
    box-shadow: 0 2px 8px rgba(49, 171, 227, 0.1);
  }

  &--active {
    border-color: #31ABE3;
    background: #eff6ff;
  }

  &--selected {
    border-color: #7c3aed;
    background: #f5f3ff;
    box-shadow: 0 0 0 2px rgba(124, 58, 237, 0.15);
  }

  .kg-file-icon {
    font-size: 18px;
    flex-shrink: 0;
  }

  .kg-file-name {
    flex: 1;
    font-size: 12px;
    color: #374151;
    word-break: break-all;
    line-height: 1.3;
  }

  .kg-file-size {
    font-size: 11px;
    color: #9ca3af;
    flex-shrink: 0;
  }

  .kg-file-check {
    font-size: 11px;
    color: #7c3aed;
    font-weight: 600;
    flex-shrink: 0;
  }

  .kg-btn-delete {
    display: none;
    background: none;
    border: none;
    color: #ef4444;
    font-size: 14px;
    font-weight: 700;
    cursor: pointer;
    padding: 2px 6px;
    border-radius: 4px;
    line-height: 1;
    flex-shrink: 0;
    transition: background 0.15s;

    &:hover {
      background: #fef2f2;
    }
  }

  &:hover .kg-btn-delete {
    display: inline-block;
  }
}

// ── 预览区 ──
.kg-preview {
  flex: 1;
  display: flex;
  flex-direction: column;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  overflow: hidden;
  min-height: 400px;
}

.kg-preview-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 14px;
  background: #f9fafb;
  border-bottom: 1px solid #e5e7eb;
  flex-shrink: 0;

  h3 {
    margin: 0;
    font-size: 13px;
    font-weight: 600;
    color: #374151;
  }
}

.kg-preview-body {
  flex: 1;
  min-height: 0;
}

.kg-iframe {
  width: 100%;
  height: 100%;
  border: none;
  display: block;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(-4px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>
