## Developer Guide

开发者需要在开发环境下安装uv。

### 项目结构

```
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

### 试运行

```bash
cd wazuh_ai_agent
uv run langgraph dev
```

### 测试

测试代码为`./tests/test_*`，基于`pytest`测试框架。

执行测试：

```bash
cd wazuh_ai_agent
# 分别测试python版本为3.11, 3.12, 3.13的测试
uv run -p 3.11 pytest 
uv run -p 3.12 pytest
uv run -p 3.13 pytest
# 覆盖率测试
uv run pytest --cov=src
uv run pytest --cov=src/agents  # 针对某个包测试覆盖率
```

### 格式化

在提交代码之前，格式化代码。

```bash
cd wazuh_ai_agent
uv run black .
uv run ruff check . --fix
```

### 语言

由于一些兼容性问题，请不要在pyproject.toml中写中文（注释也不要用中文）。
开发过程中的日志请用英文，例如

```python
logger.info("Do not use Chinese.")
```

### Windows 下 LangGraph 启动编码错误

如果运行 `uv run langgraph dev` 时在 `openapi_str = f.read()` 处出现
`UnicodeDecodeError: 'gbk'`，是因为中文 Windows 默认使用 GBK 读取了 UTF-8 文件。
在 PowerShell 中执行以下命令，永久为当前用户启用 Python UTF-8 模式：

```powershell
[Environment]::SetEnvironmentVariable("PYTHONUTF8", "1", "User")
```

执行后重新打开终端，再运行 `uv run langgraph dev`。可使用以下命令确认输出为 `utf-8`：

```powershell
uv run python -c "import locale; print(locale.getpreferredencoding(False))"
```
