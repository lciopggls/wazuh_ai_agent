# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

An AI agent system built on LangGraph (`langgraph dev`) that orchestrates multiple specialist agents to interact with the Wazuh security monitoring platform. The project uses `uv` for Python dependency management and has a Vue 3 + Vite frontend for the SOC dashboard.

## Essential Commands

```bash
# Run the LangGraph development server (all agents)
uv run langgraph dev

# Run all tests (Python 3.11/3.12/3.13)
uv run -p 3.11 pytest
uv run -p 3.12 pytest
uv run -p 3.13 pytest

# Run a single test file
uv run pytest tests/test_router_agent.py

# Coverage
uv run pytest --cov=src
uv run pytest --cov=src/agents

# Format and lint before committing
uv run black <modified_file.py>
uv run ruff check . --fix

# Frontend
cd frontend && pnpm dev      # dev server
cd frontend && pnpm build    # production build

# Topology service (standalone)
uv run wazuh-topology-api    # starts uvicorn on 0.0.0.0:8000
```

## Architecture

### Agent Graph Hierarchy (defined in `langgraph.json`)

Six LangGraph graphs are registered, all in [src/agents/agent.py](src/agents/agent.py):

```
router_agent        ← Main orchestrator (ReAct-style with tools)
  ├─ rule_agent     ← Rule CRUD + generation (multi-node StateGraph)
  ├─ attack_attributor ← Attack forensics (multi-node StateGraph)
  └─ response_agent ← IP blocking (ReAct-style with tools)

demo_agent          ← Simple Wazuh API demo
indexer_agent       ← Raw Indexer data access (standalone)
```

### Router Agent ([src/agents/router_agent.py](src/agents/router_agent.py))

The central orchestrator. Uses `create_agent` (ReAct) with four tools:
- `write_task_plan` — records a plan for multi-step requests before execution
- `delegate_rule_agent` — rule creation/modification/query/cleanup
- `delegate_attack_attribution` — attack forensics and log queries
- `delegate_response_agent` — IP blocking

**Critical design patterns:**
- **Thread-level sessions**: State is isolated per `thread_id` from LangGraph config. Each thread maintains its own `latest_plan_summary`, `executed_steps`, and `specialist_state_cache` (preserves specialist graph state across invocations).
- **High-risk authorization**: Rule verification/upload/delete and IP blocking require user approval. The router checks for risk keywords and demands the literal marker `已获用户明确授权` in the task text before proceeding.
- **Task passthrough**: User input containing JSON logs must be passed verbatim to specialists — the router must never preprocess, extract fields, or add commentary.
- **Agent→IP mapping**: Extracted from topology and injected into system prompts so users can refer to agents by IP address.

### Rule Agent ([src/agents/rule_agent/](src/agents/rule_agent/))

A multi-node `StateGraph` with these nodes and flow:

```
decision → environment_perception → requirement_understanding
  → log_retrieval_feasibility (or log_sample_processing for user-provided logs)
  → rule_generation → response (user review)
  → rule_verification (upload → restart manager → validate config → logtest)
  → response (final)
```

Decision node routes directly to `rule_verification`, `cleanup_rule`, `rule_query`, or `response` for non-generation intents.

### Attack Attribution Agent ([src/agents/attack_attribution/](src/agents/attack_attribution/))

Multi-node `StateGraph` with autonomous planning:

```
Planner_Node → Simple_Log_Query_Node (for raw log queries) / Attribution_Decision_Node
Attribution_Decision_Node → User_Input_Node (clue confirmation) / Attribution_Planner_Node
Attribution_Planner_Node → Log_Retrieval / MITRE_Expert / Reporter
Reporter → Attack_Abstract → Visualization → Graph_Filter → Attack_Graph
```

The `AttributionState` carries structured routing actions (`next_action_fromPlannerNode`, etc.), MITRE knowledge base, executed query fingerprints (dedup), and attack graph data (entities + relations).

### Wazuh API Layer ([src/wazuh_api/](src/wazuh_api/))

- `wazuh_server_token.py` — Token caching with refresh-before-expiry logic
- `server_api.py` — Full Wazuh Server REST API: agents, rules CRUD, rule files/groups, manager restart, config validation, logtest, active-response (IP blocking)
- `indexer_api.py` — OpenSearch queries against `wazuh-alerts-*` and `wazuh-archives-*` indices with helper functions for process tree traversal (parent/child/activity search)

### Configuration ([src/core/config.py](src/core/config.py))

Uses `pydantic-settings` loading from `.env`. Two LLM model configs:
- `TEST_LLM_*` — default model for router, rule, indexer, demo, response agents
- `ATTRIBUTION_*` — dedicated model for attack attribution (with extended HTTP timeout and `model_kwargs` support for DeepSeek Pro thinking-mode disable)

### Services ([src/service/](src/service/))

- `topology_service.py` — FastAPI on `:8000`, serves `/api/topo` with agent list + high-level alerts (level ≥ 10, last 30 min)
- `memory.py` — FastAPI on `:8001`, SSE streaming endpoint `/api/chat/stream` wrapping LangGraph agent execution with `astream(stream_mode="updates")`

### Frontend ([frontend/](frontend/))

Vue 3 + TypeScript + Vite. Key dependencies: Element Plus (UI), ECharts (charts), AntV X6 (topology graph), Pinia (state). Communicates with backend via REST and SSE.

## Project Conventions (from AGENTS.md)

- Always declare dependencies in `pyproject.toml` first, then `uv sync`. Never bypass project dependency config.
- Run `uv run pytest` after coding tasks.
- After Python changes, run `uv run black <modified_files>` then `uv run ruff check . --fix`.
- If black/ruff modified files, re-run relevant tests.
- No Chinese in `pyproject.toml` (comments included). Log messages must be in English.

## Testing

Tests in [tests/](tests/) use pytest. Key test files:
- `test_router_agent.py` — router delegation and authorization logic
- `test_rule_agent_graph.py` — rule agent graph nodes
- `test_indexer_agent.py` / `test_indexer_api.py` — indexer queries
- `test_server_api.py` — Wazuh server API wrappers
- `test_attack_attributor.py` — attack attribution flow
- `test_topology_api.py` / `test_wazuh_server_token.py` — services

Fixtures live in `tests/fixtures/`. `conftest.py` is currently empty.

## Known Issues

- [src/agents/rule_agent/nodes.py](src/agents/rule_agent/nodes.py) contains an unresolved git merge conflict at lines 1834–1845 (`<<<<<<< HEAD` / `>>>>>>> origin/master`) in the `rule_verification_node` function. The HEAD version skips logtest when `user_provided_full_log` is set; the `origin/master` version always runs logtest. This must be resolved before the verification flow works correctly.
