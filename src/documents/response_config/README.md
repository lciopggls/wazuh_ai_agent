# 事件响应配置：从零部署与验证

本文只记录当前版本实际需要的配置，用于在另一套环境中复现以下功能：

1. IP 封禁、解封和状态查询；
2. 入站 TCP 54321 端口封禁、解封和状态查询；
3. 指定 PID 的 `notepad.exe` 查询和终止；
4. 本地账户 `demo_user` 查询、禁用和启用。

部署目标可以是任意有效的 Windows Agent。端口、进程和账户功能仍保留脚本白名单，
不应把本文直接当作任意端口、进程或账户的通用处置方案。

## 目录导航

```text
response_config/
├─ README.md
├─ windows_agent/
│  ├─ scripts/          # Windows Active Response BAT/PowerShell 脚本
│  └─ log_collection/   # Windows Agent 结果日志采集配置
├─ wazuh_manager/
│  ├─ active_response/  # Manager Active Response 配置片段
│  └─ rules/            # Manager JSON 结果规则
├─ docs/                # IP、端口和端点响应专项文档
├─ examples/            # 完整配置参考，不能直接覆盖生产配置
└─ baseline/            # 传统人工处置基线测量工具
```

专项说明：

- [IP 响应](docs/ip_response.md)
- [端口响应](docs/port_response.md)
- [进程与账户响应](docs/endpoint_response.md)

## 1. 环境变量表

开始前记录新环境的实际值，后文中的尖括号内容均需替换：

| 变量 | 说明 |
|---|---|
| `<AGENT_ID>` | 目标 Agent 的数字 ID，例如 `005` |
| `<AGENT_IP>` | 目标 Windows Agent 的实际地址 |
| `<MANAGER_IP>` | Ubuntu Manager 的实际地址 |
| `<INDEXER_IP>` | Wazuh Indexer 的实际地址；一体化部署通常与 `<MANAGER_IP>` 相同 |
| `<UBUNTU_USER>` | 可通过 SSH 登录 Ubuntu 的用户，仅隧道方案需要 |
| `<WAZUH_API_USER>` | Wazuh Server API 用户 |
| `<INDEXER_USER>` | Indexer 用户，常见值为 `admin` |

本文基于 Ubuntu 22.04、Wazuh 4.x、Windows Agent 默认安装目录：

```text
C:\Program Files (x86)\ossec-agent
```

如果安装目录不同，必须同步替换脚本目录、日志路径和 Agent `ossec.conf` 中的路径。

## 2. 前置条件

- Ubuntu VM 已安装并启动 Wazuh Manager、Indexer 和 API。
- Windows VM 已安装 Wazuh Agent，并以有效数字 ID 注册到该 Manager。
- 宿主机已克隆本仓库并安装 `uv` 和 Git；使用可选隧道时还需要 SSH 客户端。
- 三台机器时间已同步；进程终止耗时展示依赖时间同步。
- Windows 上使用管理员 PowerShell，Ubuntu 上使用具备 `sudo` 权限的终端。

先在 Ubuntu Manager 确认 Agent 在线：

```bash
sudo /var/ossec/bin/agent_control -lc
```

必须能看到目标 Agent 为 Active，之后再继续配置。

## 3. 配置每个目标 Windows Agent

以下脚本、结果日志和 `ossec.conf` 采集项必须在每台需要执行响应动作的 Agent 上分别部署；
只在一台 Agent 上部署不会自动同步到其他 Agent。

### 3.1 备份配置并确认 Manager 地址

在管理员 PowerShell 中执行：

```powershell
$agentHome = "C:\Program Files (x86)\ossec-agent"
Copy-Item "$agentHome\ossec.conf" "$agentHome\ossec.conf.response-backup" -Force
```

打开 `$agentHome\ossec.conf`，确认 `<client>` 中的服务器地址是 Ubuntu Manager：

```xml
<client>
  <server>
    <address>&lt;MANAGER_IP&gt;</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
  <!-- 保留安装时生成的其他 client 配置 -->
</client>
```

找到 Agent 原有的 `<active-response>` 块，确保其中为：

```xml
<disabled>no</disabled>
```

不要在 Windows Agent 中添加 `block-ip`、`block-port` 或 `endpoint-response` 的
`<command>` 定义；这些命令只在 Ubuntu Manager 注册。

### 3.2 复制六个执行脚本

从仓库的 `src/documents/response_config/windows_agent/scripts/` 复制下列文件：

```text
block-ip.bat
block-ip.ps1
block-port.bat
block-port.ps1
endpoint-response.bat
endpoint-response.ps1
```

目标目录：

```text
C:\Program Files (x86)\ossec-agent\active-response\bin\
```

复制后检查：

```powershell
$bin = "$agentHome\active-response\bin"
Get-Item `
  "$bin\block-ip.bat", "$bin\block-ip.ps1", `
  "$bin\block-port.bat", "$bin\block-port.ps1", `
  "$bin\endpoint-response.bat", "$bin\endpoint-response.ps1"
```

### 3.3 添加三个结果日志采集项

在 Windows Agent 的 `ossec.conf` 文件末尾、默认结束注释之前追加一个新的
`<ossec_config>` 块：

```xml
<ossec_config>
  <localfile>
    <location>C:\Program Files (x86)\ossec-agent\active-response\block-ip-query.log</location>
    <log_format>json</log_format>
    <only-future-events>yes</only-future-events>
    <label key="@source">wazuh-ai-block-query</label>
  </localfile>

  <localfile>
    <location>C:\Program Files (x86)\ossec-agent\active-response\block-port-query.log</location>
    <log_format>json</log_format>
    <only-future-events>yes</only-future-events>
    <label key="@source">demo-port-query</label>
  </localfile>

  <localfile>
    <location>C:\Program Files (x86)\ossec-agent\active-response\endpoint-response-query.log</location>
    <log_format>json</log_format>
    <only-future-events>yes</only-future-events>
    <label key="@source">wazuh-ai-endpoint-response</label>
  </localfile>
</ossec_config>
```

仓库中对应的独立参考片段为：

- `windows_agent/log_collection/windows-agent-query.xml`
- `windows_agent/log_collection/windows-agent-port-query.xml`
- `windows_agent/log_collection/windows-agent-endpoint-response.xml`

### 3.4 创建日志、演示账户并重启 Agent

脚本首次执行时也会写日志，但部署时预先创建可避免采集器因文件不存在而等待：

```powershell
$responseDir = "$agentHome\active-response"
@(
  "$responseDir\block-ip-query.log",
  "$responseDir\block-port-query.log",
  "$responseDir\endpoint-response-query.log"
) | ForEach-Object {
  if (-not (Test-Path $_)) { New-Item -ItemType File -Path $_ -Force }
}

Restart-Service -Name wazuh
Start-Sleep -Seconds 15
Get-Service -Name wazuh
```

预期状态为 `Running`。

随后通过“计算机管理 → 本地用户和组 → 用户”手动创建本地普通账户：

```text
demo_user
```

不要把它加入 Administrators 组，也不要用它登录。AI 只负责查询、禁用和启用，不负责创建。

## 4. Ubuntu Manager 配置

### 4.1 备份 `ossec.conf`

```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.response-backup
```

### 4.2 注册三个命令和九个命令变体

编辑 `/var/ossec/etc/ossec.conf`。在第一个 `<ossec_config>` 内的
`<!-- Active response -->` 区域加入以下内容；不要粘贴到 Windows Agent：

```xml
<command>
  <name>block-ip</name>
  <executable>block-ip.bat</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<command>
  <name>block-port</name>
  <executable>block-port.bat</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<command>
  <name>endpoint-response</name>
  <executable>endpoint-response.bat</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>block-ip</command>
  <location>local</location>
  <rules_id>999991</rules_id>
  <timeout>600</timeout>
</active-response>

<active-response>
  <disabled>no</disabled>
  <command>block-ip</command>
  <location>local</location>
  <rules_id>999992</rules_id>
  <timeout>3600</timeout>
</active-response>

<active-response>
  <disabled>no</disabled>
  <command>block-ip</command>
  <location>local</location>
  <rules_id>999993</rules_id>
  <timeout>86400</timeout>
</active-response>

<active-response>
  <disabled>no</disabled>
  <command>block-ip</command>
  <location>local</location>
  <rules_id>999994</rules_id>
</active-response>

<active-response>
  <disabled>no</disabled>
  <command>endpoint-response</command>
  <location>local</location>
  <rules_id>999995</rules_id>
</active-response>

<active-response>
  <disabled>no</disabled>
  <command>block-port</command>
  <location>local</location>
  <rules_id>999996</rules_id>
  <timeout>30</timeout>
</active-response>

<active-response>
  <disabled>no</disabled>
  <command>block-port</command>
  <location>local</location>
  <rules_id>999997</rules_id>
  <timeout>60</timeout>
</active-response>

<active-response>
  <disabled>no</disabled>
  <command>block-port</command>
  <location>local</location>
  <rules_id>999998</rules_id>
  <timeout>300</timeout>
</active-response>

<active-response>
  <disabled>no</disabled>
  <command>block-port</command>
  <location>local</location>
  <rules_id>999999</rules_id>
</active-response>
```

同一片段保存在仓库的
`wazuh_manager/active_response/ossec_ar_fix.xml`。各 API 命令名称如下：

| 功能 | 后端调用的命令 |
|---|---|
| IP 定时/永久封禁 | `block-ip600`、`block-ip3600`、`block-ip86400`、`block-ip0` |
| 端口定时/手动解封/查询 | `block-port30`、`block-port60`、`block-port300`、`block-port0` |
| 进程和账户操作 | `endpoint-response0` |

注意：IP 默认封禁时长是 10 分钟；端口默认封禁时长才是 30 秒。事件响应智能体等待
Agent、Manager 和 Indexer 返回验证结果的最长时间是 60 秒；底层 Server API 直接调用时
仍默认 30 秒。这两个等待值都不是防火墙规则的有效期。

### 4.3 安装三个 JSON 结果规则

把仓库中的规则文件传到 Ubuntu Manager，并安装到 `/var/ossec/etc/rules/`：

| 仓库文件 | Manager 目标文件 | 规则 ID |
|---|---|---:|
| `manager-query-rule.xml` | `wazuh_ai_block_query.xml` | 100210 |
| `manager-endpoint-response-rule.xml` | `wazuh_ai_endpoint_response.xml` | 100211 |
| `manager-port-query-rule.xml` | `demo_port_query.xml` | 100212 |

可在宿主机仓库根目录用 SCP 传输：

```powershell
scp `
  .\src\documents\response_config\wazuh_manager\rules\manager-query-rule.xml `
  .\src\documents\response_config\wazuh_manager\rules\manager-endpoint-response-rule.xml `
  .\src\documents\response_config\wazuh_manager\rules\manager-port-query-rule.xml `
  <UBUNTU_USER>@<MANAGER_IP>:/tmp/
```

然后在 Ubuntu 上执行：

```bash
sudo cp /tmp/manager-query-rule.xml /var/ossec/etc/rules/wazuh_ai_block_query.xml
sudo cp /tmp/manager-endpoint-response-rule.xml /var/ossec/etc/rules/wazuh_ai_endpoint_response.xml
sudo cp /tmp/manager-port-query-rule.xml /var/ossec/etc/rules/demo_port_query.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/wazuh_ai_block_query.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/wazuh_ai_endpoint_response.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/demo_port_query.xml
sudo chmod 660 /var/ossec/etc/rules/wazuh_ai_block_query.xml
sudo chmod 660 /var/ossec/etc/rules/wazuh_ai_endpoint_response.xml
sudo chmod 660 /var/ossec/etc/rules/demo_port_query.xml
```

如果新 Manager 已占用规则 ID `100210`～`100212`，必须先改为未占用的自定义 ID，
并同步修改下文的日志检查命令。后端按 `request_id` 查询结果，不需要因此修改 Python 代码。

同样应确认 `ossec.conf` 中的 `rules_id` `999991`～`999999` 没有被现有自动响应占用；
如有冲突，可换成其他未占用 ID。API 命令名称由命令名和超时时间生成，不需要修改后端。

### 4.4 检查并重启 Manager

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager
sudo /var/ossec/bin/agent_control -lc
```

必须满足：配置检查无错误、Manager 为 `active (running)`、目标 Agent 为 Active。

## 5. 宿主机后端连接

### 5.1 配置 `.env`

在仓库根目录从 `.env.example` 创建 `.env`，填写实际账号和密码：

```dotenv
WAZUH_SERVER_API_PROTOCOL="https"
WAZUH_SERVER_API_HOST="<MANAGER_IP>"
WAZUH_SERVER_API_PORT="55000"
WAZUH_SERVER_API_USERNAME="<WAZUH_API_USER>"
WAZUH_SERVER_API_PASSWORD="<WAZUH_API_PASSWORD>"
WAZUH_SERVER_AUTH_TOKEN_EXP_TIMEOUT="900"

WAZUH_INDEXER_HOST="<INDEXER_IP>"
WAZUH_INDEXER_PORT="9200"
WAZUH_INDEXER_USER="<INDEXER_USER>"
WAZUH_INDEXER_PASSWORD="<INDEXER_PASSWORD>"
```

保留项目原有的模型配置。`.env` 含密码，不要提交到 Git。

如果 Manager 和 Indexer 位于同一台 Ubuntu 主机，`<INDEXER_IP>` 通常直接填写
`<MANAGER_IP>`。

### 5.2 验证 Indexer 直连

默认使用后端主机直连 Indexer 的方式：

```powershell
Test-NetConnection <INDEXER_IP> -Port 9200
curl.exe -k -u <INDEXER_USER> https://<INDEXER_IP>:9200
```

`TcpTestSucceeded` 应为 `True`；输入密码后应返回 Indexer 信息。`Unauthorized` 表示网络
已经连通但账号或密码不正确。直连端口只能向可信后端主机开放，不得暴露到公网。

### 5.3 可选：建立 Indexer SSH 隧道

如果直连不可达，或者安全策略不允许开放 9200，可在单独的宿主机 PowerShell 窗口运行：

```powershell
ssh -N -L 127.0.0.1:19200:127.0.0.1:9200 <UBUNTU_USER>@<MANAGER_IP>
```

保持窗口开启，将 `.env` 中的 Indexer 地址改为：

```dotenv
WAZUH_INDEXER_HOST="127.0.0.1"
WAZUH_INDEXER_PORT="19200"
```

然后测试：

```powershell
curl.exe -k -u INDEXER_USER https://127.0.0.1:19200
```

出现密码提示并返回 Indexer 信息即表示连接正常。

### 5.4 启动后端

在仓库根目录执行：

```powershell
$env:UV_CACHE_DIR = "$PWD\.uv-cache"
uv sync
uv run langgraph dev
```

修改脚本、虚拟机配置或 `.env` 后，应停止旧后端再重新启动，并在页面创建新对话。

## 6. 用总控 `router_agent` 完整验证

在 LangGraph 页面选择 `router_agent` 并创建新对话。下面所有请求都直接输入总控页面，
不需要手动切换到 `response_agent`。
执行示例前，将文本中的 `<AGENT_ID>` 替换为目标 Agent 的实际数字 ID，例如 `005`。

`router_agent` 应识别事件响应意图，将任务委派给 `response_agent`，再在当前对话中返回
执行结果和真实状态证据。只要下面四组测试都通过，就同时验证了总控路由、响应智能体、
后端 API、Manager、Agent 和结果回传链路。

### 6.1 IP 封禁、查询和解封

使用文档保留地址 `203.0.113.10`，避免误操作真实业务地址：

```text
查询 Agent <AGENT_ID> 是否封禁了 203.0.113.10
在 Agent <AGENT_ID> 上双向封禁 203.0.113.10，持续 10 分钟
查询 Agent <AGENT_ID> 是否封禁了 203.0.113.10
在 Agent <AGENT_ID> 上解除对 203.0.113.10 的封禁
```

预期依次看到未封禁、已封禁且包含入站和出站证据、已封禁、已解除。

Windows 交叉检查：

```powershell
netsh advfirewall firewall show rule name=all | Select-String "Wazuh_AI_Block_"
Get-Content "$agentHome\active-response\block-ip-query.log" -Tail 20
```

### 6.2 端口封禁、查询和解封

在 Windows Agent 创建临时允许规则并启动测试服务：

```powershell
New-NetFirewallRule `
  -DisplayName "Demo_Allow_In_TCP_54321" `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 54321

python -m http.server 54321 --bind 0.0.0.0
```

保持 HTTP 服务窗口开启。在 Ubuntu 上先确认能够访问：

```bash
curl --connect-timeout 3 http://<AGENT_IP>:54321
```

然后在页面输入：

```text
查询 Agent <AGENT_ID> 的 54321 端口是否被封禁
在 Agent <AGENT_ID> 上封禁 54321 端口
解除 Agent <AGENT_ID> 上 54321 端口的封禁
```

未指定时长默认 30 秒；也只接受 60 秒和 300 秒。封禁后 Ubuntu 的 `curl` 应失败，
解封或超时后应恢复。以下请求必须被拒绝且不能产生防火墙规则：

```text
在 Agent <AGENT_ID> 上封禁 54322 端口 30 秒
在 Agent <AGENT_ID> 上封禁 54321 端口 45 秒
```

### 6.3 进程查询和终止

在 Windows Agent 打开记事本，再查询实际 PID：

```powershell
Get-Process -Name notepad | Select-Object Id, ProcessName
```

将 `<PID>` 替换为刚查到的数值，在页面输入：

```text
查询 Agent <AGENT_ID> 上 PID <PID> 的进程
终止 Agent <AGENT_ID> 上 PID <PID> 的可疑进程
```

预期只允许 `notepad.exe`，终止后窗口关闭。交叉检查应无输出：

```powershell
Get-Process -Id <PID> -ErrorAction SilentlyContinue
```

### 6.4 账户查询、禁用和启用

```text
查询 Agent <AGENT_ID> 上 demo_user 的状态
禁用 Agent <AGENT_ID> 上的 demo_user
启用 Agent <AGENT_ID> 上的 demo_user
```

Windows 交叉检查：

```powershell
Get-CimInstance -ClassName Win32_UserAccount `
  -Filter "LocalAccount=True AND Name='demo_user'" |
Select-Object Name, Disabled, SID
```

禁用后 `Disabled=True`，启用后 `Disabled=False`。演示结束时保持账户启用。

## 7. 可选：直接进入 specialist 排错

正常部署和展示不需要进入另外两个智能体。只有 `router_agent` 未正确调用功能时，才使用
相同请求进行分层定位：

1. 直接进入 `response_agent` 测试；如果它成功，问题位于 Router 的意图识别或委派链路；
2. 如果 specialist 同样失败，按照下一节检查 Manager、Agent、Indexer 和日志回传链路。

不要为了抽测而在多个智能体中连续执行相同的定时封禁；尚未到期的旧 `delete` 事件可能
影响下一轮演示。

## 8. 故障定位

出现 `unknown（状态未知）` 时，按下面顺序检查，不要只看 Active Response API 是否返回成功：

1. Windows Agent 服务是否为 `Running`；
2. `active-responses.log` 是否收到命令；
3. 三个结构化结果日志是否出现相同 `request_id`；
4. Ubuntu Manager 是否产生规则 `100210`、`100211` 或 `100212` 的告警；
5. Indexer 直连是否正常；使用隧道时确认 SSH 窗口是否仍在运行；
6. `.env` 中的 Manager、Indexer 地址和账号是否正确；
7. 修改 `.env` 后是否重启了后端并创建了新对话。

Windows 日志：

```powershell
Get-Content "$agentHome\active-response\active-responses.log" -Tail 100
Get-Content "$agentHome\active-response\block-ip-query.log" -Tail 20
Get-Content "$agentHome\active-response\block-port-query.log" -Tail 20
Get-Content "$agentHome\active-response\endpoint-response-query.log" -Tail 20
```

Ubuntu Manager 日志：

```bash
sudo tail -n 200 /var/ossec/logs/ossec.log
sudo grep -E '100210|100211|100212' /var/ossec/logs/alerts/alerts.json | tail -n 20
```

API 返回成功只代表命令已发送给 Agent。只有 Agent 的实际结果经过 Manager 和 Indexer
回传后，页面显示的“已验证成功”才代表动作真正生效。

## 9. 演示后清理

1. 在页面解除测试 IP 和端口封禁；
2. 等待所有定时封禁到期后再开始下一轮；
3. 确保 `demo_user` 已重新启用；
4. 在 Windows 停止测试 HTTP 服务并删除临时允许规则：

```powershell
Remove-NetFirewallRule -DisplayName "Demo_Allow_In_TCP_54321" -ErrorAction SilentlyContinue
```

5. 不再测试时按 `Ctrl+C` 停止后端；使用隧道时同时停止 SSH 隧道。

## 10. 部署文件清单

目录中的部署源文件如下：

```text
windows_agent/scripts/
  block-ip.bat
  block-ip.ps1
  block-port.bat
  block-port.ps1
  endpoint-response.bat
  endpoint-response.ps1
windows_agent/log_collection/
  windows-agent-query.xml
  windows-agent-port-query.xml
  windows-agent-endpoint-response.xml
wazuh_manager/active_response/
  ossec_ar_fix.xml
wazuh_manager/rules/
  manager-query-rule.xml
  manager-port-query-rule.xml
  manager-endpoint-response-rule.xml
examples/
  ossec.conf
baseline/
  measure-legacy-notepad-response.ps1
```
