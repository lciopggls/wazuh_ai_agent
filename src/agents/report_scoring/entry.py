from langchain_openai import ChatOpenAI

from agents.report_scoring.graph import get_report_scoring_graph
from core.config import settings
from service.report_scoring.context_loader import create_default_scoring_context_loader

model = ChatOpenAI(
    model=settings.TEST_LLM_MODEL,
    api_key=settings.TEST_LLM_API_KEY,
    base_url=settings.TEST_LLM_BASE_URL,
)
report_scoring_agent = get_report_scoring_graph(
    model,
    create_default_scoring_context_loader(),
)
