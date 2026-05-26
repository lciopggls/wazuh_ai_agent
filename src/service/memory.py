import uvicorn
import json
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import AsyncGenerator
from fastapi.middleware.cors import CORSMiddleware
# LangChain / LangGraph 导入
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
# 假设的项目结构
from src.agents.agent import get_demo_agent
from src.agents.agent import get_attack_attribution_agent
from src.agents.agent import get_rule_generator_agent
from src.agents.agent import get_router_agent
from core.config import settings
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
    streaming=True # 开启 LLM 的流式支持
)
# 初始化智能体注册表
def initialize_agents():
    # 实际开发中，这里可以针对不同 agent_id 加载不同的 graph
    return {
        "router_agent": get_router_agent(llm,llm,llm,checkpointer=memory),
        "attack_attribution": get_attack_attribution_agent(llm, checkpointer=memory),
    }
agents_registry = initialize_agents()
class ChatInput(BaseModel):
    message: str
    thread_id: str
    agent_id: str = "rule_generator"
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
            input_state,
            config=config,
            stream_mode="updates"
        ):
            # event 格式: { "节点名称": { "messages": ..., "attack_abstract": ... } }
            for node_name, output in event.items():
                payload = {
                    "node": node_name,
                    "role": "assistant"
                }

                # 情况 1：节点更新了消息 (对话文本)
                if "messages" in output and output["messages"]:
                    last_msg = output["messages"][-1]
                    content = last_msg.content if hasattr(last_msg, 'content') else str(last_msg)
                    payload["type"] = "message"
                    payload["content"] = content
                    yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"

                # 情况 2：关键节点生成了攻击摘要 (JSON 字典)
                if "attack_abstract" in output and output["attack_abstract"] is not None:
                    payload["type"] = "abstract"
                    #  修复：将字典序列化为 JSON 字符串后再行赋值
                    payload["content"] = json.dumps(output["attack_abstract"], ensure_ascii=False, indent=2)
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
    return StreamingResponse(
        event_generator(data),
        media_type="text/event-stream"
    )
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001) 