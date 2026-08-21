import httpx
from langchain_openai import ChatOpenAI

from agents.attack_attribution.attack_attributor import get_attack_attribution_agent
from agents.baseline.baseline_agent_plus import get_baseline_agent_plus
from agents.baseline.baseline_agent_simple import get_baseline_agent_simple
from agents.demo_agent import get_demo_agent
from agents.response_agent import get_response_agent
from agents.router_agent import get_router_agent
from agents.rule_agent.rule_agent import get_rule_agent
from core.config import settings
from core.model_configs import get_model_kwargs

model = ChatOpenAI(
    model=settings.TEST_LLM_MODEL,
    api_key=settings.TEST_LLM_API_KEY,
    base_url=settings.TEST_LLM_BASE_URL,
)

# 自定义 HTTP 客户端，专门解决 chunked read 报错
custom_http_client = httpx.Client(
    timeout=httpx.Timeout(
        connect=30.0,
        read=300.0,  # 将读取超时延长至 5 分钟，给足大模型输出的时间
        write=30.0,
        pool=30.0,
    )
)

llm_attribution_params = {
    "model": settings.ATTRIBUTION_LLM_MODEL,
    "api_key": settings.ATTRIBUTION_API_KEY,
    "base_url": settings.ATTRIBUTION_LLM_BASE_URL,
    "http_client": custom_http_client,
    "max_retries": 2,
}

special_kwargs = get_model_kwargs(settings.ATTRIBUTION_LLM_MODEL)
if special_kwargs:
    llm_attribution_params["model_kwargs"] = special_kwargs

model_attribution = ChatOpenAI(**llm_attribution_params)

demo_agent = get_demo_agent(model)
rule_agent = get_rule_agent(model)
attack_attributor = get_attack_attribution_agent(model_attribution)
baseline_agent_plus = get_baseline_agent_plus(model)
baseline_agent_simple = get_baseline_agent_simple(model)
router_agent = get_router_agent(
    model, rule_model=model, attack_model=model_attribution, response_model=model
)
response_agent = get_response_agent(model)
