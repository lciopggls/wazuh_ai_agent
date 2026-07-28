import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import datetime
from collections.abc import AsyncGenerator
from pathlib import Path

import uvicorn
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# LangChain / LangGraph 导入
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from core.config import settings

# 假设的项目结构
from src.agents.agent import get_attack_attribution_agent, get_router_agent

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
    # 实际开发中，这里可以针对不同 agent_id 加载不同的 graph
    return {
        "router_agent": get_router_agent(llm, llm, llm, checkpointer=memory),
        "attack_attribution": get_attack_attribution_agent(llm, checkpointer=memory),
    }


agents_registry = initialize_agents()


class ChatInput(BaseModel):
    message: str
    thread_id: str
    agent_id: str = "rule_generator"


class SaveReportInput(BaseModel):
    content: str
    filename: str | None = None  # 可选，不传则自动生成


async def event_generator(data: ChatInput) -> AsyncGenerator[str, None]:
    """
    流式生成器：捕获 LangGraph 每个节点的完整输出，动态封装并推送至前端
    """
    agent_executor = agents_registry.get(data.agent_id)
    if not agent_executor:
        yield f"data: {json.dumps({'error': 'Agent not found'})}\n\n"
        return

    config = {"configurable": {"thread_id": data.thread_id}}
    input_state = {"messages": [{"role": "user", "content": data.message}]}

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

# ── 知识图谱路径配置 ──
_KG_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "knowledge_graph",
)
KG_INPUT_DIR = os.path.join(_KG_ROOT, "input")
KG_OUTPUT_DIR = os.path.join(_KG_ROOT, "output")
KG_GALLERY_DIR = os.path.join(_KG_ROOT, "gallery")
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".md"}


@app.post("/api/report/save")
async def save_report(data: SaveReportInput):
    """
    保存攻击溯源报告到本地 knowledge_graph/input 目录
    """
    try:
        os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = data.filename or f"attack_trace_report_{timestamp}.md"
        # 确保扩展名是 .md
        if not filename.endswith(".md"):
            filename += ".md"
        filepath = os.path.join(REPORT_OUTPUT_DIR, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(data.content)

        return {
            "status": "ok",
            "filepath": filepath,
            "filename": filename,
            "message": f"报告已保存: {filename}",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


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
                files.append({
                    "name": f,
                    "size": os.path.getsize(fpath),
                    "mtime": os.path.getmtime(fpath),
                })
        return {"status": "ok", "files": files}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/knowledge-graph/gallery/{filename:path}")
async def kg_get_gallery_file(filename: str):
    """返回 gallery 中指定 HTML 文件的内容"""
    safe_name = Path(filename).name
    fpath = os.path.join(KG_GALLERY_DIR, safe_name)
    if not os.path.isfile(fpath):
        raise HTTPException(status_code=404, detail="文件不存在")
    with open(fpath, "r", encoding="utf-8") as f:
        content = f.read()
    return {"status": "ok", "name": safe_name, "content": content}


@app.get("/api/knowledge-graph/output")
async def kg_list_output():
    """列出 output 目录下所有生成的 HTML 图谱文件"""
    try:
        os.makedirs(KG_OUTPUT_DIR, exist_ok=True)
        files = []
        for f in sorted(os.listdir(KG_OUTPUT_DIR)):
            if f.endswith(".html"):
                fpath = os.path.join(KG_OUTPUT_DIR, f)
                files.append({
                    "name": f,
                    "size": os.path.getsize(fpath),
                    "mtime": os.path.getmtime(fpath),
                })
        return {"status": "ok", "files": files}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/knowledge-graph/output/{filename:path}")
async def kg_get_output_file(filename: str):
    """返回 output 中指定 HTML 文件的内容"""
    safe_name = Path(filename).name
    fpath = os.path.join(KG_OUTPUT_DIR, safe_name)
    if not os.path.isfile(fpath):
        raise HTTPException(status_code=404, detail="文件不存在")
    with open(fpath, "r", encoding="utf-8") as f:
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
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/knowledge-graph/generate")
async def kg_generate():
    """运行 AttacKG 知识图谱生成流水线"""
    try:
        os.makedirs(KG_INPUT_DIR, exist_ok=True)
        os.makedirs(KG_OUTPUT_DIR, exist_ok=True)

        script_path = os.path.join(_KG_ROOT, "AttacKG_Run.py")
        if not os.path.isfile(script_path):
            raise HTTPException(status_code=500, detail=f"脚本不存在: {script_path}")

        # 检查 input 目录是否有支持的文件
        input_files = [
            f for f in os.listdir(KG_INPUT_DIR)
            if f.endswith((".txt", ".md", ".pdf"))
        ]
        if not input_files:
            raise HTTPException(status_code=400, detail="input 目录中没有可处理的文件（仅支持 txt / pdf / md）")

        result = subprocess.run(
            [sys.executable, "-B", script_path],
            capture_output=True, text=True, timeout=300,
            cwd=_KG_ROOT,
        )

        if result.returncode != 0:
            return {
                "status": "error",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "message": "图谱生成失败",
            }

        # 收集 output 文件列表
        output_files = [
            f for f in sorted(os.listdir(KG_OUTPUT_DIR))
            if f.endswith(".html")
        ]

        return {
            "status": "ok",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "output_files": output_files,
            "message": f"图谱生成完成，共 {len(output_files)} 个文件",
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="图谱生成超时（300秒）")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001)
