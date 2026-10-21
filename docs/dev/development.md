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
pnpm test:topology
```

- `pnpm dev`：启动前端开发服务；
- `pnpm build`：构建前端项目；
- `pnpm preview`：预览构建结果；
- `pnpm type-check`：执行 Vue/TypeScript 类型检查；
- `pnpm test:chat-persistence`：运行聊天记录持久化测试；
- `pnpm test:topology`：运行拓扑设备分页、告警聚合和异常响应测试。

### 拓扑数据来源

拓扑组件直接通过已有的同源代理访问 Wazuh，不再运行独立的拓扑 API 服务：

- `/wazuh-api`：认证和设备列表。
- `/wazuh-indexer`：告警聚合查询。

设备列表按 ID 排序分页获取；告警按 Agent 聚合近 30 分钟、等级不低于 10 的记录，并选取最高等级告警。请求失败时显示错误并保留上次成功结果，不自动加载示例数据。

前端使用 `frontend/.env.development` 中的 Wazuh 和 Indexer 认证信息，与首页其他组件保持一致。修改配置后需重启前端服务。

Vite 的 `server.proxy` 用于开发服务。部署构建后的 `dist` 时，需要在 Nginx 等网关配置相同的路径转发，并去除代理路径前缀；构建产物自身不提供代理。Indexer 可通过 `VITE_WAZUH_INDEXER_HOST` 配置独立主机，默认与 Wazuh Server 共用主机。

中心节点优先显示 Wazuh 返回的实际地址；返回回环地址（如 `127.0.0.1`、`::1`）或未指定地址时，显示 `VITE_WAZUH_SERVER_API_HOST`。请将该配置填写为 Wazuh 服务端的实际 IP 或域名，不使用访问者电脑的地址。

仅拓扑功能需要启动前端并能连接 Wazuh；对话功能仍需启动对话后端。

### 对话服务和远程访问

前端通过同源路径 `/soc-api` 访问 8001 服务，包含流式对话、报告保存和知识图谱接口。开发代理将该路径转发到前端服务所在机器的 `http://127.0.0.1:8001` 并去除 `/soc-api` 前缀。因此前端和对话服务应在同一台服务器启动，其他电脑只需访问该服务器的前端地址，无需直接连接 8001。

静态部署时需在网关配置相同的路径转发。对流式对话应关闭响应缓冲（Nginx 的 `proxy_buffering off`），并为长时间调查设置足够的读取超时。

后端使用 `MemorySaver`，按请求中的 `thread_id` 保存进程内上下文；同一个后端进程和同一个线程可连续对话。后端重启或请求被分配到另一个独立进程时，不共享该内存。前端的会话列表和线程映射保存于各浏览器的 `localStorage`，不自动跨电脑同步。页面显示的历史聊天记录不等同于后端仍保留上下文。

## 语言约定

由于兼容性问题，不要在 `pyproject.toml` 中写中文，包括注释。开发过程中的日志使用英文。

```python
logger.info("Do not use Chinese.")
```
