"""Stage 1: Rewrite CTI reports organized by MITRE ATT&CK tactics."""
import os, sys
_KG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _KG_ROOT)
import time
import json
import re
import asyncio
from os import path as op

import openai
import tiktoken

from pdfminer.high_level import extract_text as pdfminer_extract_text

from template import rewriting_template, Tactic_label_order
from openai import OpenAI
from config import openai_api_key, openai_api_base, current_model


client = OpenAI(
    api_key=openai_api_key,
    base_url=openai_api_base,
)

usage_save_dir = f'./dataset_CTI/usage/rewriting/{current_model}'


def async_wrap(func, args):
    return asyncio.to_thread(func, **args)


def openai_usage2dict(usage):
    return {
        "prompt_tokens": usage.prompt_tokens,
        "completion_tokens": usage.completion_tokens,
        "total_tokens": usage.total_tokens
    }


def num_tokens_from_string(string: str, model_name: str) -> int:
    try:
        encoding = tiktoken.encoding_for_model(model_name)
    except KeyError:
        encoding = tiktoken.encoding_for_model('gpt-4o')
    return len(encoding.encode(string))


def _normalize_bilingual_headers(text: str, tactics: list) -> str:
    """Normalize bilingual markdown headers from LLM output.
    Handles formats like:
      ### 4. 执行 (Execution)         →  ### Execution
      #### 1. 侦察 (Reconnaissance)   →  #### Reconnaissance
      **防御规避 (Defense Evasion)**   →  **Defense Evasion**
      ### 其他 (Others)               →  ### Others
    """
    if not text:
        return text
    tactic_names = '|'.join(re.escape(t) for t in tactics + ['Others'])
    # Match: line-start, `#`/`**` prefix, optional `Num. `, any text, then `(EnglishName)` at end
    # Uses `.*` before the parenthesized English name to handle Chinese/any content
    pattern = re.compile(
        r'(^|\n)(#{1,6}\s+|\*\*)(?:\d+\.\s+)?.*?\((' + tactic_names + r')\)',
        re.MULTILINE
    )
    return pattern.sub(r'\1\2\3', text)


def _parse_rewrite_response(raw_text: str, mitre: dict) -> dict:
    """Parse LLM response into {tactic_name: summary_text} dict.
    Layers: bilingual-normalization → JSON → markdown-headers → plain-text headers → fallback."""

    raw_text = raw_text.strip()
    if raw_text.startswith('```'):
        lines = raw_text.split('\n')
        raw_text = '\n'.join(lines[1:-1]) if len(lines) > 2 else raw_text

    tactics = [t['name'] for t in mitre['tactics']]

    # Normalize bilingual headers (DeepSeek often returns Chinese + English)
    raw_text = _normalize_bilingual_headers(raw_text, tactics)

    # Helper: split text by markdown headers (# to ######, ** bold)
    def _split_by_md_headers(text: str) -> dict:
        md_result = {}
        md_pattern = r'(?:\*\*|#{1,6}\s?)(' + '|'.join(re.escape(t) for t in tactics) + r'|Others)(?:\*\*)?\s*\n?'
        md_parts = re.split(md_pattern, text)
        if len(md_parts) > 1:
            for i in range(1, len(md_parts), 2):
                key = md_parts[i].strip()
                value = md_parts[i + 1].strip() if i + 1 < len(md_parts) else ''
                md_result[key] = value
        return md_result

    # Layer 1: JSON parse
    try:
        result = json.loads(raw_text)
        if isinstance(result, dict):
            first_key = list(result.keys())[0] if result else ''
            if first_key and first_key.strip() in Tactic_label_order:
                # If all content is under "Others", try markdown split
                if len(result) == 1 and 'Others' in result:
                    md = _split_by_md_headers(result['Others'])
                    if md:
                        return md
                return result
    except (json.JSONDecodeError, ValueError):
        pass

    # Layer 2: Markdown headers on raw text
    md = _split_by_md_headers(raw_text)
    if md:
        return md

    # Layer 3: "TacticName:\ncontent..." format
    result = {}
    pattern = '(' + '|'.join(re.escape(t) + ':' for t in tactics) + '|' + 'Others:' + ')'
    parts = re.split(pattern, raw_text, flags=re.MULTILINE)
    for i in range(1, len(parts), 2):
        key = parts[i].rstrip(':').strip()
        value = parts[i + 1].strip() if i + 1 < len(parts) else ''
        result[key] = value
    if result:
        return result

    # Layer 4: Fallback to Others
    return {'Others': raw_text}


def request_rewriting(report_dir, mitre, file_name='', ext='.txt',
                      model=current_model, temperature=0, max_token=120000):
    file_path = op.join(report_dir, file_name + ext)
    if ext.lower() == '.pdf':
        text = pdfminer_extract_text(file_path)
    else:
        with open(file_path, 'r', encoding='utf-8') as f:
            text = f.read()

    messages, tools = rewriting_template(text, mitre)
    num_token = sum(num_tokens_from_string(m["content"], model) for m in messages)
    if num_token > max_token:
        print(f"Messages skipped (token overflow), file = {file_name}")
        return None

    while True:
        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                tools=tools,
                tool_choice="auto",
                temperature=temperature,
                max_tokens=16000,
            )
            if response.choices[0].message.tool_calls:
                # Structured response via function calling
                arguments = response.choices[0].message.tool_calls[0].function.arguments
                result = json.loads(arguments)
                # Map underscore keys back to tactic names (DeepSeek workaround)
                key_map = {
                    'Resource_Development': 'Resource Development',
                    'Initial_Access': 'Initial Access',
                    'Privilege_Escalation': 'Privilege Escalation',
                    'Defense_Evasion': 'Defense Evasion',
                    'Credential_Access': 'Credential Access',
                    'Lateral_Movement': 'Lateral Movement',
                    'Command_and_Control': 'Command and Control',
                }
                mapped = {}
                for k, v in result.items():
                    mapped[key_map.get(k, k)] = v
                result = mapped
                # Remove None-valued entries (tactics not present in the report)
                result = {k: v for k, v in result.items() if v not in (None, 'None', '')}
                # Ensure at least 'Others' exists as fallback
                if not result:
                    result = {'Others': 'No specific tactic content identified.'}
            else:
                # Fall back to text parsing
                raw_content = response.choices[0].message.content
                result = _parse_rewrite_response(raw_content, mitre)

            usage_dir = usage_save_dir
            os.makedirs(usage_dir, exist_ok=True)
            with open(op.join(usage_dir, file_name + '.json'), 'w', encoding='utf-8') as f:
                json.dump(openai_usage2dict(response.usage), f, indent=4)

            return {
                "result": result,
                "finish_reason": response.choices[0].finish_reason,
                "usage": openai_usage2dict(response.usage),
                "name": file_name,
            }
        except openai.RateLimitError:
            time.sleep(3)
        except openai.APIConnectionError:
            time.sleep(1)
        except openai.AuthenticationError as e:
            print(e)
            return None
        except openai.BadRequestError as e:
            print(e)
            return None


async def request_files(input_dir=None, skip_existed=True):
    file_dir = input_dir or os.path.join(_KG_ROOT, 'input')
    save_dir = os.path.join(_KG_ROOT, 'data', '1_rewrite')
    mitre_json_path = os.path.join(_KG_ROOT, 'data', 'mitre.json')

    with open(mitre_json_path, 'r') as f:
        mitre = json.load(f)

    os.makedirs(save_dir, exist_ok=True)
    os.makedirs(usage_save_dir, exist_ok=True)

    tasks = []
    for file in os.listdir(file_dir):
        name, ext = op.splitext(file)
        if skip_existed and op.exists(op.join(save_dir, name + '.json')):
            continue
        args = {'report_dir': file_dir, 'mitre': mitre, 'file_name': name,
                'ext': ext, 'model': current_model, "max_token": 120000}
        tasks.append(async_wrap(request_rewriting, args))

    sub_task_step = 20
    for i in range(0, len(tasks), sub_task_step):
        sub_tasks = tasks[i:i + sub_task_step]
        responses = await asyncio.gather(*sub_tasks)
        for response in responses:
            if response is None:
                continue
            with open(op.join(save_dir, response['name'] + '.json'), 'w', encoding='utf-8') as f:
                try:
                    json.dump(response['result'], f, indent=4)
                except Exception:
                    pass


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-dir', default=os.path.join(_KG_ROOT, 'input') + '/')
    args = parser.parse_args()
    asyncio.run(request_files(input_dir=args.input_dir))
