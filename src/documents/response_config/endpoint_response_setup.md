# Agent 001 进程终止与账户控制部署验证

本文部署两个仅供演示的 Windows Active Response 功能：

- 查询或终止 Agent 001 上指定 PID 的 `notepad.exe`。
- 查询、禁用或启用 Agent 001 上固定的本地账户 `demo_user`。

两个功能只返回 `success`、`failed`、`unknown` 三种状态，并通过 Agent 查询真实状态、
Manager 规则、Indexer 告警和唯一 `request_id` 完成验证。现有 `block-ip` 文件和配置无需修改。

## 1. 在 Agent 001 创建演示账户

在 Agent 001 打开“计算机管理 → 本地用户和组 → 用户”，手动创建：

```text
demo_user
```

不要让这个账户加入 Administrators 组，演示时也不要使用它登录。AI 不负责创建账户，也不会
强制注销已有会话。

管理员 PowerShell 检查：

```powershell
Get-CimInstance -ClassName Win32_UserAccount `
  -Filter "LocalAccount=True AND Name='demo_user'" |
Select-Object Name, Disabled, SID
```

必须能看到一条本地账户记录。

## 2. 更新 Agent 001 脚本

把项目中的以下两个文件复制到 Agent 001：

```text
endpoint-response.bat
endpoint-response.ps1
```

目标目录：

```text
C:\Program Files (x86)\ossec-agent\active-response\bin\
```

确认脚本存在：

```powershell
$bin = "C:\Program Files (x86)\ossec-agent\active-response\bin"
Get-Item "$bin\endpoint-response.bat", "$bin\endpoint-response.ps1"
```

脚本包含双重限制：只允许 `notepad.exe`，账户名称必须严格等于 `demo_user`。

## 3. 配置 Agent 001 采集结果日志

打开 Agent 001 的：

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

把 `windows-agent-endpoint-response.xml` 中的完整 `<ossec_config>` 块追加到文件末尾：

```xml
<ossec_config>
  <localfile>
    <location>C:\Program Files (x86)\ossec-agent\active-response\endpoint-response-query.log</location>
    <log_format>json</log_format>
    <only-future-events>yes</only-future-events>
    <label key="@source">wazuh-ai-endpoint-response</label>
  </localfile>
</ossec_config>
```

创建日志并重启 Agent：

```powershell
$resultLog = "C:\Program Files (x86)\ossec-agent\active-response\endpoint-response-query.log"
if (-not (Test-Path $resultLog)) {
    New-Item -ItemType File -Path $resultLog -Force
}

Restart-Service -Name wazuh
Start-Sleep -Seconds 15
Get-Service -Name wazuh
```

预期服务状态为 `Running`。

## 4. 配置 Ubuntu Manager 命令

在 Ubuntu Manager 的 `/var/ossec/etc/ossec.conf` 中，放在 `<ossec_config>` 内的 Active
Response 配置区域：

```xml
<command>
  <name>endpoint-response</name>
  <executable>endpoint-response.bat</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>endpoint-response</command>
  <location>local</location>
  <rules_id>999995</rules_id>
</active-response>
```

后台通过 Wazuh API 调用的命令名称是 `endpoint-response0`；末尾的 `0` 表示这个命令没有
自动撤销超时。

## 5. 安装 Manager 查询结果规则

把 `manager-endpoint-response-rule.xml` 复制为：

```text
/var/ossec/etc/rules/wazuh_ai_endpoint_response.xml
```

执行：

```bash
sudo chown wazuh:wazuh /var/ossec/etc/rules/wazuh_ai_endpoint_response.xml
sudo chmod 660 /var/ossec/etc/rules/wazuh_ai_endpoint_response.xml
sudo /var/ossec/bin/wazuh-analysisd -t
```

配置检查无错误后重启：

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager
```

查询结果规则 ID 为 `100211`。如果你的 Manager 已经占用该 ID，需要同时修改 XML 中的 ID
和本文档中的检查命令。

## 6. 启动后端

继续保持现有 Windows 到 Indexer 的 SSH 隧道和 `.env` 配置，不需要为新功能增加端口。

停止旧进程，然后在项目根目录重新启动：

```powershell
$env:UV_CACHE_DIR = "$PWD\.uv-cache"
uv run langgraph dev
```

在页面选择 `demo_agent` 并创建新会话。

## 7. 验证进程查询与终止

在 Agent 001 打开一个记事本，然后在管理员 PowerShell 查询 PID：

```powershell
Get-Process -Name notepad | Select-Object Id, ProcessName
```

假设 PID 为 `4321`，在 `demo_agent` 输入：

```text
查询 Agent 001 上 PID 4321 的进程
```

预期：

```text
success（已验证成功）
进程名称：notepad.exe
进程当前存在：是
```

然后输入：

```text
终止 Agent 001 上 PID 4321 的可疑进程
```

记事本窗口应该关闭，页面预期：

```text
success（已验证成功）
进程名称：notepad.exe
进程当前存在：否
```

本机交叉验证：

```powershell
Get-Process -Id 4321 -ErrorAction SilentlyContinue
```

正常情况下没有输出。再次终止同一个已不存在的 PID 应返回 `failed`，不能误报为 AI 成功
终止。如果 PID 对应的不是 `notepad.exe`，脚本也必须返回 `failed`。

## 8. 验证账户查询、禁用与启用

先输入：

```text
查询 Agent 001 上 demo_user 的状态
```

预期返回 `success`，并展示当前为启用或禁用。

禁用账户：

```text
禁用 Agent 001 上的 demo_user
```

预期：

```text
success（已验证成功）
账户当前状态：禁用
```

Agent 001 交叉验证：

```powershell
Get-CimInstance -ClassName Win32_UserAccount `
  -Filter "LocalAccount=True AND Name='demo_user'" |
Select-Object Name, Disabled, SID
```

此时 `Disabled` 应为 `True`。重复禁用仍应返回 `success`，并说明原状态已经符合要求。

重新启用：

```text
启用 Agent 001 上的 demo_user
```

预期返回 `success`，本机查询的 `Disabled` 应恢复为 `False`。演示结束时务必让
`demo_user` 保持启用状态。

## 9. 检查完整回传链路

Agent 001 的动作日志：

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Tail 50
```

Agent 001 的结构化结果日志：

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\endpoint-response-query.log" -Tail 20
```

成功事件应包含：

```json
{"event_type":"wazuh_ai_endpoint_response_result","request_id":"...","action":"terminate_process","operation_status":"success"}
```

Manager 检查规则 100211 告警：

```bash
sudo grep 'wazuh_ai_endpoint_response' /var/ossec/logs/alerts/alerts.json | tail -n 10
```

## 10. 状态解释与故障定位

- `success（已验证成功）`：Agent 已执行动作并返回符合预期的实际状态。
- `failed（执行失败）`：目标不存在、不符合白名单、命令执行报错或实际状态未生效。
- `unknown（状态未知）`：命令已经投递，但 30 秒内没有从 Indexer 取得对应 `request_id`
  的结果。

出现 `unknown` 时依次检查：

1. `endpoint-response-query.log` 是否生成了相同 `request_id` 的 JSON。
2. Agent 的 `ossec.conf` 是否采集该日志，Wazuh Agent 是否为 `Running`。
3. Manager 的规则 100211 是否命中。
4. Windows 后端到 Indexer 的 SSH 隧道是否仍在运行。
5. `.env` 中的 Indexer 主机、端口和账号是否仍然正确。
