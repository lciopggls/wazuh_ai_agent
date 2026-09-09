# 开发者说明

开发者需要在开发环境下安装 uv。

## 项目结构

```text
WAZUH_AI_AGENT
├─src
│  ├─agents
│  ├─core
│  └─wazuh_api
├─tests
├─pyproject.toml
├─docs
└─uv.lock
```

## 试运行

```powershell
Set-Location "<项目根目录>"
uv run langgraph dev
```

## 测试

测试代码为 `./tests/test_*`，基于 `pytest` 测试框架。

```powershell
Set-Location "<项目根目录>"

# 分别使用 Python 3.11、3.12、3.13 运行测试
uv run -p 3.11 pytest
uv run -p 3.12 pytest
uv run -p 3.13 pytest

# 覆盖率测试
uv run pytest --cov=src
uv run pytest --cov=src/agents
```

## 格式化

提交代码之前执行格式化和代码检查：

```powershell
Set-Location "<项目根目录>"
uv run black .
uv run ruff check . --fix
```

## 前端开发补充

前端目录：

```powershell
Set-Location "<项目根目录>\frontend"
```

常用命令：

```powershell
pnpm dev
pnpm build
pnpm preview
pnpm type-check
pnpm test:chat-persistence
```

- `pnpm dev`：启动前端开发服务；
- `pnpm build`：构建前端项目；
- `pnpm preview`：预览构建结果；
- `pnpm type-check`：执行 Vue/TypeScript 类型检查；
- `pnpm test:chat-persistence`：运行聊天记录持久化测试。

### 拓扑数据来源

前端优先从 `http://127.0.0.1:8000/api/topo` 获取实时拓扑数据，可以通过 `VITE_TOPOLOGY_API_URL` 修改接口地址。

当实时拓扑接口不可用时，前端会自动使用示例数据 `public/topology/agents_topo_data.json`。

仅进行前端界面开发时，可以只启动前端服务；需要实时拓扑数据或完整功能时，仍需启动对应后端服务。

## 语言约定

由于兼容性问题，不要在 `pyproject.toml` 中写中文，包括注释。开发过程中的日志使用英文。

```python
logger.info("Do not use Chinese.")
```
