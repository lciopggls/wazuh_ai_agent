"""
AttacKG+ shared configuration.
Reads LLM credentials from the .env file at the project root.
No external dependencies required.
"""
import os
import sys

# Locate the .env file: project root (3 levels up from src/knowledge_graph/)
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_env_path = os.path.join(_project_root, '.env')

_config = {}
if os.path.exists(_env_path):
    with open(_env_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                _config[key] = value

LLM_MODEL = _config.get('TEST_LLM_MODEL', 'gpt-4o')
LLM_API_KEY = _config.get('TEST_LLM_API_KEY', '')
LLM_BASE_URL = _config.get('TEST_LLM_BASE_URL', '')

# Convenience aliases (used by existing scripts)
openai_api_key = LLM_API_KEY
openai_api_base = LLM_BASE_URL
current_model = LLM_MODEL

__all__ = [
    'LLM_MODEL', 'LLM_API_KEY', 'LLM_BASE_URL',
    'openai_api_key', 'openai_api_base', 'current_model',
]
