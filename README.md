# 电网网络安全数智分析平台部署文档

本文用于指导**电网网络安全数智分析平台**的首次部署与后续启动。
请按章节顺序完成服务端、采集客户端和项目配置，并将命令中的占位符替换为实际值。

## 目录

1. [基础安全环境部署](#第一章-基础安全环境部署)
2. [AI 运维平台部署](#第二章-ai-运维平台部署)
3. [项目配置与可选扩展](#第三章-项目配置与可选扩展)
4. [故障排查](#第四章-故障排查)
5. [开发者附录](#第五章-开发者附录)

## 部署说明

- 命令中的 `<中心服务端IP>`、`<项目根目录>` 等内容需要替换为实际值。
- 第一章部署基础环境，包含中心服务端和采集客户端；第二章部署本项目本身。

# 第一章 基础安全环境部署

## 1.1 部署条件

中心服务端使用 64 位 **Linux**，支持 Intel/AMD 和 ARM 架构。已验证的系统版本如下：

- Amazon Linux 2、Amazon Linux 2023
- CentOS Stream 10
- Red Hat Enterprise Linux 7、8、9、10
- Ubuntu 16.04、18.04、20.04、22.04、24.04

单机部署的参考资源如下。该表用于容量估算，不是绝对限制。

| 采集客户端数量 | CPU | 内存 | 存储（约 90 天） |
| --- | ---: | ---: | ---: |
| 1–25 | 4 vCPU | 8 GiB | 50 GB |
| 25–50 | 8 vCPU | 8 GiB | 100 GB |
| 50–100 | 8 vCPU | 8 GiB | 200 GB |

超过 100 个采集客户端时，应根据实际数据量进行分布式规划。本文不展开分布式部署命令。

## 1.2 服务端部署

### 1.2.1 首次部署

在中心服务端执行：

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

安装完成后，终端会输出 Web 控制台地址及登录凭据，请妥善保存。

### 1.2.2 获取服务端认证信息

安装完成后，在 `wazuh-install-files.tar` 所在目录执行以下命令，查看服务端 API 和索引服务用户密码：

```bash
sudo tar -O -xvf wazuh-install-files.tar \
  wazuh-install-files/wazuh-passwords.txt
```

将输出中的密码分别填写到项目配置文件：

- 服务端 API 用户 `wazuh`：
  - 后端 `.env`：`WAZUH_SERVER_API_USERNAME`、`WAZUH_SERVER_API_PASSWORD`；
  - 前端 `.env.development`：`VITE_WAZUH_SERVER_API_USERNAME`、`VITE_WAZUH_SERVER_API_PASSWORD`。
- 索引服务用户 `admin`：
  - 后端 `.env`：`WAZUH_INDEXER_USER`、`WAZUH_INDEXER_PASSWORD`；
  - 前端 `.env.development`：`VITE_WAZUH_INDEXER_USER`、`VITE_WAZUH_INDEXER_PASSWORD`。

## 1.3 客户端部署

### 1.3.1 Linux 采集客户端首次部署

以下命令需要 root 权限。以 Debian/Ubuntu 系统为例：

```bash
sudo apt-get install -y gnupg apt-transport-https
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | sudo gpg --no-default-keyring \
      --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
sudo WAZUH_MANAGER="<中心服务端IP>" apt-get install -y wazuh-agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

RHEL、CentOS Stream、Amazon Linux 等 RPM 系统使用对应的仓库配置和包管理器：

```bash
sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
sudo tee /etc/yum.repos.d/wazuh.repo > /dev/null <<'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
priority=1
EOF
sudo dnf install -y wazuh-agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

安装后将采集客户端版本与中心服务端版本保持兼容，避免自动升级造成版本不一致。

### 1.3.2 Windows 采集客户端首次部署

以管理员身份打开 PowerShell，下载当前版本 MSI 安装包并完成安装：

```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi" `
  -OutFile ".\wazuh-agent-4.14.7-1.msi"
msiexec.exe /i .\wazuh-agent-4.14.7-1.msi /q WAZUH_MANAGER="<中心服务端IP>"
Start-Service wazuhsvc
```

### 1.3.3 采集客户端后续启动

Linux：

```bash
sudo systemctl start wazuh-agent
```

Windows PowerShell：

```powershell
Start-Service wazuhsvc
```

# 第二章 AI 运维平台部署

## 2.1 首次部署条件

项目运行端使用 Windows，并满足：

- Python 3.11 或更高版本；
- `uv`；
- Node.js 20.11 或更高版本；
- `pnpm` 9 或更高版本；
- 可访问项目依赖源、模型服务、中心服务端 API 和索引服务。

## 2.2 首次部署

### 2.2.1 安装运行工具

使用 PowerShell：

```powershell
winget install --id astral-sh.uv -e --accept-source-agreements --accept-package-agreements
uv --version
uv python install 3.11

winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements
node --version
corepack enable
corepack prepare pnpm@latest --activate
pnpm --version
```

### 2.2.2 安装后端依赖

```powershell
Set-Location "<项目根目录>"
Copy-Item .env.example .env
uv sync
notepad .env
```

根据实际环境填写 `.env` 中的中心服务端 API、索引服务和模型服务配置。

### 2.2.3 安装前端依赖

```powershell
Set-Location "<项目根目录>\frontend"
Copy-Item .env.example .env.development
pnpm install
notepad .env.development
```

前端默认地址为 `http://127.0.0.1:8112`。

## 2.3 后续启动

每次启动项目时分别打开三个 PowerShell 窗口。

窗口一：启动对话服务。

```powershell
Set-Location "<项目根目录>"
uv run python -m src.service.memory
```

窗口二：启动拓扑服务。

```powershell
Set-Location "<项目根目录>"
uv run wazuh-topology-api
```

窗口三：启动前端。

```powershell
Set-Location "<项目根目录>\frontend"
pnpm dev
```

默认服务地址：

| 服务 | 地址 |
| --- | --- |
| 对话服务 | `http://127.0.0.1:8001` |
| 拓扑服务 | `http://127.0.0.1:8000/api/topo` |
| 前端 | `http://127.0.0.1:8112` |

## 2.4 可选：启动图工作流调试服务

仅在需要调试 LangGraph 工作流时执行：

```powershell
Set-Location "<项目根目录>"
uv run langgraph dev
```

# 第三章 项目配置与可选扩展

## 3.1 配置文件

后端配置文件：`<项目根目录>\.env`

至少需要根据实际环境填写：

- `WAZUH_SERVER_API_*`：中心服务端 API 地址、端口和认证信息；
- `WAZUH_INDEXER_*`：索引服务地址、端口和认证信息；
- `TEST_LLM_*`：对话服务使用的模型、密钥和服务地址；
- `ATTRIBUTION_LLM_*`：攻击溯源使用的模型、密钥和服务地址，可以和TEST_LLM_*保持一致也可以使用不同的模型。

前端配置文件：`<项目根目录>\frontend\.env.development`

- `VITE_WAZUH_SERVER_API_*`：与后端对应的中心服务端 API 配置；
- `VITE_WAZUH_INDEXER_*`：前端需要使用的索引服务配置；
- `VITE_TOPOLOGY_API_URL`：保持为拓扑服务地址，默认是 `http://127.0.0.1:8000/api/topo`。

## 3.2 知识图谱扩展

首次使用知识图谱功能时执行：

```powershell
Set-Location "<项目根目录>"
uv run python -m spacy download en_core_web_sm
uv run python -c "import nltk; nltk.download('punkt')"
```

知识图谱的具体使用方式见：[使用手册](docs/manual/README.md)。

## 3.3 事件响应扩展

事件响应相关部署和配置见：`src/documents/response_config/README.md`。

## 3.4 其他相关文档

- [使用手册](docs/manual/README.md)：介绍平台界面和主要功能的使用方法；
- [开发者说明](docs/dev/development.md)：介绍项目结构、测试、代码检查和前端开发命令。

# 第四章 故障排查

## 4.1 依赖安装失败

```powershell
uv --version
uv sync
pnpm --version
Set-Location "<项目根目录>\frontend"
pnpm install
```

如果前端依赖安装提示需要确认构建脚本，按提示执行 `pnpm approve-builds` 后再次运行 `pnpm install`。

## 4.2 后端服务无法启动

检查以下内容：

- 根目录 `.env` 是否存在，模型服务配置是否完整；
- 中心服务端 API 和索引服务地址、端口、账号密码是否正确；
- 8001 或 8000 端口是否已被其他进程占用。

## 4.3 前端无法访问后端

检查三个服务是否都已启动，并确认 `frontend\.env.development` 中的 `VITE_TOPOLOGY_API_URL` 与拓扑服务地址一致。

## 4.4 采集客户端没有数据

检查采集客户端服务是否运行、中心服务端地址是否填写正确，以及网络是否放行客户端到中心服务端的通信端口。

# 第五章 开发者附录

## 5.1 测试与代码检查

在项目根目录执行：

```powershell
uv run pytest
uv run ruff check . --fix
```

修改 Python 文件后，先执行对应文件的格式化：

```powershell
uv run black <修改的Python文件路径>
```

## 5.2 主要目录

- `src/agents/`：智能体实现；
- `src/wazuh_api/`：中心服务端 API 和索引服务 API 封装；
- `src/service/`：对话服务和拓扑服务；
- `frontend/`：前端项目；
- `src/documents/response_config/`：事件响应配置文档。
