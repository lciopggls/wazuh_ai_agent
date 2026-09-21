import asyncio
import hashlib
import json
import logging
import os
import shutil
import sys
import uuid
from collections.abc import AsyncGenerator
from datetime import datetime
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

# LangChain / LangGraph 导入
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from pydantic import BaseModel

from core.config import settings

logger = logging.getLogger(__name__)

app = FastAPI(title="Wazuh SOC Multi-Agent Streaming API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
memory = MemorySaver()
llm = ChatOpenAI(
    model=settings.TEST_LLM_MODEL,
    api_key=settings.TEST_LLM_API_KEY,
    base_url=settings.TEST_LLM_BASE_URL,
    streaming=True,  # 开启 LLM 的流式支持
)


# 初始化智能体注册表
def initialize_agents():
    # 延迟导入，避免报告保存等独立接口在模块导入时连接 Wazuh。
    from agents.agent import (
        get_attack_attribution_agent,
        get_router_agent,
    )

    return {
        "router_agent": get_router_agent(llm, llm, llm, checkpointer=memory),
        "attack_attribution": get_attack_attribution_agent(llm, checkpointer=memory),
    }


agents_registry = None


def get_agents_registry():
    global agents_registry
    if agents_registry is None:
        agents_registry = initialize_agents()
    return agents_registry


class ChatInput(BaseModel):
    message: str
    thread_id: str
    agent_id: str = "rule_generator"
    visualization_requested: bool = False


class SaveReportInput(BaseModel):
    content: str
    filename: str | None = None  # 可选，不传则自动生成


async def event_generator(data: ChatInput) -> AsyncGenerator[str, None]:
    """
    流式生成器：捕获 LangGraph 每个节点的完整输出，动态封装并推送至前端
    """
    agent_executor = get_agents_registry().get(data.agent_id)
    if not agent_executor:
        yield f"data: {json.dumps({'error': 'Agent not found'})}\n\n"
        return

    config = {
        "configurable": {
            "thread_id": data.thread_id,
            "visualization_requested": data.visualization_requested,
        }
    }
    input_state = {"messages": [{"role": "user", "content": data.message}]}
    if data.agent_id == "attack_attribution":
        input_state["visualization_requested"] = data.visualization_requested

    try:
        # 使用 stream_mode="updates" 模式
        async for event in agent_executor.astream(
            input_state, config=config, stream_mode="updates"
        ):
            # event 格式: { "节点名称": { "messages": ..., "attack_abstract": ... } }
            for node_name, output in event.items():
                payload = {"node": node_name, "role": "assistant"}

                # 情况 1：节点更新了消息 (对话文本)
                if "messages" in output and output["messages"]:
                    last_msg = output["messages"][-1]
                    content = last_msg.content if hasattr(last_msg, "content") else str(last_msg)
                    payload["type"] = "message"
                    payload["content"] = content
                    yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"

                # 情况 2：关键节点生成了攻击摘要 (JSON 字典)
                if "attack_abstract" in output and output["attack_abstract"] is not None:
                    payload["type"] = "abstract"
                    #  修复：将字典序列化为 JSON 字符串后再行赋值
                    payload["content"] = json.dumps(
                        output["attack_abstract"], ensure_ascii=False, indent=2
                    )
                    yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"

        # 传输结束标志
        yield "data: [DONE]\n\n"

    except Exception as e:
        error_msg = {"status": "error", "message": str(e)}
        yield f"data: {json.dumps(error_msg)}\n\n"


@app.post("/api/chat/stream")
async def chat_stream(data: ChatInput):
    """
    流式对话接口
    """
    return StreamingResponse(event_generator(data), media_type="text/event-stream")


# ── 报告保存配置 ──
# 输出目录：攻击溯源报告的保存路径
REPORT_OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "knowledge_graph",
    "input",
)

MAX_REPORT_BYTES = 1024 * 1024


class ReportSaveError(Exception):
    """Structured error returned by the local report-save endpoint."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 400,
        field: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.field = field

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.field is not None:
            payload["field"] = self.field
        return payload


def _save_report_to_output(content: str, requested_filename: str | None) -> Path:
    """Persist one local Markdown report without overwriting different content."""

    if not content.strip():
        raise ReportSaveError("EMPTY_REPORT", "报告内容不能为空")
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_REPORT_BYTES:
        raise ReportSaveError("FILE_TOO_LARGE", "报告文件不能超过 1 MiB")

    output_root = Path(REPORT_OUTPUT_DIR)
    output_root.mkdir(parents=True, exist_ok=True)
    resolved_root = output_root.resolve()

    if requested_filename:
        filename = Path(requested_filename.strip()).name
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        digest = hashlib.sha256(encoded).hexdigest()[:10]
        filename = f"attack_trace_report_{timestamp}_{digest}.md"
    if not filename or filename in {".", ".."}:
        raise ReportSaveError("INVALID_REPORT_FILENAME", "报告文件名无效", field="filename")
    if not filename.lower().endswith(".md"):
        filename += ".md"
    if len(filename) > 255:
        raise ReportSaveError(
            "INVALID_REPORT_FILENAME", "报告文件名不能超过 255 个字符", field="filename"
        )

    base = Path(filename)
    for sequence in range(1, 1001):
        candidate_name = base.name if sequence == 1 else f"{base.stem}-{sequence}{base.suffix}"
        candidate = output_root / candidate_name
        if candidate.resolve().parent != resolved_root:
            raise ReportSaveError(
                "INVALID_REPORT_FILENAME", "报告文件路径超出允许目录", field="filename"
            )
        try:
            with candidate.open("xb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            return candidate
        except FileExistsError:
            try:
                if candidate.is_file() and candidate.read_bytes() == encoded:
                    return candidate
            except OSError:
                pass
            continue
        except OSError:
            raise ReportSaveError(
                "REPORT_SAVE_FAILED", "报告无法写入本地输出目录", status_code=500
            ) from None

    raise ReportSaveError("REPORT_SAVE_FAILED", "无法为报告分配唯一文件名", status_code=500)


# ── 知识图谱路径配置 ──
_KG_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "knowledge_graph",
)
KG_INPUT_DIR = os.path.join(_KG_ROOT, "input")
KG_OUTPUT_DIR = os.path.join(_KG_ROOT, "output")
KG_GALLERY_DIR = os.path.join(_KG_ROOT, "gallery")
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".md"}

_KG_TASKS: dict[str, dict[str, Any]] = {}
_KG_ACTIVE_TASK_ID: str | None = None
_KG_BACKGROUND_TASKS: set[asyncio.Task[None]] = set()


def _kg_task_timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _kg_task_response(task: dict[str, Any], message: str | None = None) -> dict[str, Any]:
    response = {"status": "ok", **task}
    if message is not None:
        response["message"] = message
    return response


def _update_kg_task(task_id: str, **changes: Any) -> None:
    task = _KG_TASKS.get(task_id)
    if task is not None:
        task.update(changes)


async def _run_kg_generation(task_id: str, script_path: str) -> None:
    global _KG_ACTIVE_TASK_ID

    process: asyncio.subprocess.Process | None = None
    _update_kg_task(task_id, task_status="running", started_at=_kg_task_timestamp())
    try:
        child_env = os.environ.copy()
        child_env["PYTHONUTF8"] = "1"
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-B",
            script_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=_KG_ROOT,
            env=child_env,
        )
        stdout_bytes, stderr_bytes = await process.communicate()
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        if process.returncode != 0:
            _update_kg_task(
                task_id,
                task_status="failed",
                finished_at=_kg_task_timestamp(),
                returncode=process.returncode,
                stdout=stdout,
                stderr=stderr,
                message="图谱生成失败",
            )
            return

        output_files = [
            filename for filename in sorted(os.listdir(KG_OUTPUT_DIR)) if filename.endswith(".html")
        ]
        _update_kg_task(
            task_id,
            task_status="succeeded",
            finished_at=_kg_task_timestamp(),
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            output_files=output_files,
            message=f"图谱生成完成，共 {len(output_files)} 个文件",
        )
    except asyncio.CancelledError:
        if process is not None and process.returncode is None:
            process.terminate()
            await process.wait()
        _update_kg_task(
            task_id,
            task_status="cancelled",
            finished_at=_kg_task_timestamp(),
            message="图谱生成任务已取消",
        )
        raise
    except Exception as exc:
        logger.exception("知识图谱后台任务执行失败")
        _update_kg_task(
            task_id,
            task_status="failed",
            finished_at=_kg_task_timestamp(),
            message="图谱生成失败",
            error=str(exc),
        )
    finally:
        if _KG_ACTIVE_TASK_ID == task_id:
            _KG_ACTIVE_TASK_ID = None


def _discard_kg_background_task(task: asyncio.Task[None]) -> None:
    _KG_BACKGROUND_TASKS.discard(task)
    if not task.cancelled():
        task.exception()


@app.post("/api/report/save")
async def save_report(data: SaveReportInput):
    """
    保存攻击溯源报告到本地 knowledge_graph/input 目录
    """
    try:
        saved_path = _save_report_to_output(data.content, data.filename)
        filename = saved_path.name
        filepath = str(saved_path)

        return {
            "status": "ok",
            "filepath": filepath,
            "filename": filename,
            "message": f"报告已保存: {filename}",
        }
    except ReportSaveError as exc:
        return {"status": "error", **exc.as_dict()}
    except Exception:
        logger.exception("报告保存失败")
        return {
            "status": "error",
            "code": "REPORT_SAVE_FAILED",
            "message": "报告保存失败",
        }


# ──────────────────────────────────────────────
# 知识图谱 API
# ──────────────────────────────────────────────


@app.get("/api/knowledge-graph/gallery")
async def kg_list_gallery():
    """列出 gallery 目录下所有 HTML 图谱文件"""
    try:
        os.makedirs(KG_GALLERY_DIR, exist_ok=True)
        files = []
        for f in sorted(os.listdir(KG_GALLERY_DIR)):
            if f.endswith(".html"):
                fpath = os.path.join(KG_GALLERY_DIR, f)
                files.append(
                    {
                        "name": f,
                        "size": os.path.getsize(fpath),
                        "mtime": os.path.getmtime(fpath),
                    }
                )
        return {"status": "ok", "files": files}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/knowledge-graph/gallery/{filename:path}")
async def kg_get_gallery_file(filename: str):
    """返回 gallery 中指定 HTML 文件的内容"""
    safe_name = Path(filename).name
    fpath = os.path.join(KG_GALLERY_DIR, safe_name)
    if not os.path.isfile(fpath):
        raise HTTPException(status_code=404, detail="文件不存在")
    with open(fpath, encoding="utf-8") as f:
        content = f.read()
    return {"status": "ok", "name": safe_name, "content": content}


@app.delete("/api/knowledge-graph/gallery/{filename:path}")
async def kg_delete_gallery_file(filename: str):
    """删除 gallery 中指定的图谱文件"""
    safe_name = Path(filename).name
    fpath = os.path.join(KG_GALLERY_DIR, safe_name)
    if not os.path.isfile(fpath):
        raise HTTPException(status_code=404, detail="文件不存在")
    try:
        os.remove(fpath)
        return {"status": "ok", "message": f"文件 {safe_name} 已删除"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/knowledge-graph/output")
async def kg_list_output():
    """列出 output 目录下所有生成的 HTML 图谱文件"""
    try:
        os.makedirs(KG_OUTPUT_DIR, exist_ok=True)
        files = []
        for f in sorted(os.listdir(KG_OUTPUT_DIR)):
            if f.endswith(".html"):
                fpath = os.path.join(KG_OUTPUT_DIR, f)
                files.append(
                    {
                        "name": f,
                        "size": os.path.getsize(fpath),
                        "mtime": os.path.getmtime(fpath),
                    }
                )
        return {"status": "ok", "files": files}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/knowledge-graph/output/{filename:path}")
async def kg_get_output_file(filename: str):
    """返回 output 中指定 HTML 文件的内容"""
    safe_name = Path(filename).name
    fpath = os.path.join(KG_OUTPUT_DIR, safe_name)
    if not os.path.isfile(fpath):
        raise HTTPException(status_code=404, detail="文件不存在")
    with open(fpath, encoding="utf-8") as f:
        content = f.read()
    return {"status": "ok", "name": safe_name, "content": content}


@app.post("/api/knowledge-graph/upload")
async def kg_upload_file(file: UploadFile = File(...)):
    """上传文件到 input 目录，仅支持 txt / pdf / md"""
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"不支持的文件格式 '{ext}'，仅支持 txt、pdf、md",
        )
    try:
        os.makedirs(KG_INPUT_DIR, exist_ok=True)
        # 避免重名覆盖
        dest = os.path.join(KG_INPUT_DIR, file.filename or f"upload_{uuid.uuid4().hex}{ext}")
        if os.path.exists(dest):
            name_stem = os.path.splitext(file.filename or "file")[0]
            dest = os.path.join(KG_INPUT_DIR, f"{name_stem}_{uuid.uuid4().hex}{ext}")

        content = await file.read()
        with open(dest, "wb") as f:
            f.write(content)

        return {
            "status": "ok",
            "filename": os.path.basename(dest),
            "filepath": dest,
            "message": f"文件 {file.filename} 上传成功",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/api/knowledge-graph/generate", status_code=202)
async def kg_generate():
    """启动 AttacKG 知识图谱后台任务并立即返回任务标识。"""
    global _KG_ACTIVE_TASK_ID

    os.makedirs(KG_INPUT_DIR, exist_ok=True)
    os.makedirs(KG_OUTPUT_DIR, exist_ok=True)

    script_path = os.path.join(_KG_ROOT, "AttacKG_Run.py")
    if not os.path.isfile(script_path):
        raise HTTPException(status_code=500, detail=f"脚本不存在: {script_path}")

    input_files = sorted(
        filename
        for filename in os.listdir(KG_INPUT_DIR)
        if filename.endswith((".txt", ".md", ".pdf"))
    )
    if not input_files:
        raise HTTPException(
            status_code=400, detail="input 目录中没有可处理的文件（仅支持 txt / pdf / md）"
        )

    if _KG_ACTIVE_TASK_ID is not None:
        active_task = _KG_TASKS.get(_KG_ACTIVE_TASK_ID)
        if active_task is not None and active_task["task_status"] in {"queued", "running"}:
            return _kg_task_response(active_task, "图谱生成任务正在后台运行")
        _KG_ACTIVE_TASK_ID = None

    task_id = f"kg_{uuid.uuid4().hex}"
    task_record = {
        "task_id": task_id,
        "task_status": "queued",
        "created_at": _kg_task_timestamp(),
        "started_at": None,
        "finished_at": None,
        "input_files": input_files,
        "output_files": [],
        "returncode": None,
        "stdout": "",
        "stderr": "",
    }
    _KG_TASKS[task_id] = task_record
    _KG_ACTIVE_TASK_ID = task_id

    background_task = asyncio.create_task(_run_kg_generation(task_id, script_path))
    _KG_BACKGROUND_TASKS.add(background_task)
    background_task.add_done_callback(_discard_kg_background_task)

    return _kg_task_response(task_record, "图谱生成任务已进入后台")


@app.get("/api/knowledge-graph/generate/status")
async def kg_generation_status(task_id: str | None = None):
    """查询指定任务；未指定 task_id 时返回当前或最近一次任务。"""
    if task_id is not None:
        task = _KG_TASKS.get(task_id)
    elif _KG_ACTIVE_TASK_ID is not None:
        task = _KG_TASKS.get(_KG_ACTIVE_TASK_ID)
    else:
        task = next(reversed(_KG_TASKS.values()), None)

    if task is None:
        raise HTTPException(status_code=404, detail="没有可查询的图谱生成任务")
    return _kg_task_response(task)


@app.post("/api/knowledge-graph/save-to-gallery")
async def kg_save_to_gallery(data: dict):
    """将 output 中的指定图谱文件复制到 gallery 目录"""
    filename = data.get("filename", "")
    if not filename:
        raise HTTPException(status_code=400, detail="缺少 filename 参数")

    safe_name = Path(filename).name
    src = os.path.join(KG_OUTPUT_DIR, safe_name)
    if not os.path.isfile(src):
        raise HTTPException(status_code=404, detail=f"output 中不存在文件: {safe_name}")

    try:
        os.makedirs(KG_GALLERY_DIR, exist_ok=True)
        dst = os.path.join(KG_GALLERY_DIR, safe_name)
        shutil.copy2(src, dst)
        return {
            "status": "ok",
            "filename": safe_name,
            "filepath": dst,
            "message": f"图谱 {safe_name} 已存入 gallery",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001)
