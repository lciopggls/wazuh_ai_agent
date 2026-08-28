# Windows Agent 进程终止与账户控制部署验证

完整环境、Manager、Indexer 和后端部署顺序见 [主部署文档](../README.md)。本文分别说明
进程响应和账户响应，但二者共用同一套 Agent 脚本、结果日志和 Manager 规则。

本文部署两个仅供演示的 Windows Active Response 功能：

- 查询或终止指定 Agent 上指定 PID 的 `notepad.exe`。
- 查询、禁用或启用指定 Agent 上固定的本地账户 `demo_user`。

两个功能只返回 `success`、`failed`、`unknown` 三种状态，并通过 Agent 查询真实状态、
Manager 规则、Indexer 告警和唯一 `request_id` 完成验证。现有 `block-ip` 文件和配置无需修改。

支持任意有效的数字 Agent ID，但以下脚本、日志采集配置和演示账户必须在每个目标 Agent
上分别部署。

## 1. 在目标 Agent 创建演示账户

在目标 Agent 打开“计算机管理 → 本地用户和组 → 用户”，手动创建：

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

## 2. 更新目标 Agent 脚本

把项目中的以下两个文件复制到目标 Agent：

```text
../windows_agent/scripts/endpoint-response.bat
../windows_agent/scripts/endpoint-response.ps1
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

## 3. 配置目标 Agent 采集结果日志

打开目标 Agent 的：

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

把 `../windows_agent/log_collection/windows-agent-endpoint-response.xml` 中的完整
`<ossec_config>` 块追加到文件末尾：

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

同一完整片段位于 `../wazuh_manager/active_response/ossec_ar_fix.xml`。

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

把 `../wazuh_manager/rules/manager-endpoint-response-rule.xml` 上传并复制为：

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

继续使用主部署文档中的 Indexer 直连配置；如果当前环境使用可选 SSH 隧道，则保持隧道
窗口运行。不需要为端点响应增加其他端口。

停止旧进程，然后在项目根目录重新启动：

```powershell
$env:UV_CACHE_DIR = "$PWD\.uv-cache"
uv run langgraph dev
```

在页面选择 `router_agent` 并创建新会话。正常验证由总控路由到事件响应智能体；只有路由
排错时才直接进入 `response_agent`。

## 7. 验证进程查询与终止

在目标 Agent 打开一个记事本，然后在管理员 PowerShell 查询 PID：

```powershell
Get-Process -Name notepad | Select-Object Id, ProcessName
```

将 `<PID>` 替换为刚查到的数值，在 `router_agent` 输入：

```text
查询 Agent <AGENT_ID> 上 PID <PID> 的进程
```

预期：

```text
success（已验证成功）
进程名称：notepad.exe
进程当前存在：是
```

然后输入：

```text
终止 Agent <AGENT_ID> 上 PID <PID> 的可疑进程
```

记事本窗口应该关闭，页面预期：

```text
success（已验证成功）
进程名称：notepad.exe
进程当前存在：否
```

本机交叉验证：

```powershell
Get-Process -Id <PID> -ErrorAction SilentlyContinue
```

正常情况下没有输出。再次终止同一个已不存在的 PID 应返回 `failed`，不能误报为 AI 成功
终止。如果 PID 对应的不是 `notepad.exe`，脚本也必须返回 `failed`。

## 8. 验证账户查询、禁用与启用

先输入：

```text
查询 Agent <AGENT_ID> 上 demo_user 的状态
```

预期返回 `success`，并展示当前为启用或禁用。

禁用账户：

```text
禁用 Agent <AGENT_ID> 上的 demo_user
```

预期：

```text
success（已验证成功）
账户当前状态：禁用
```

目标 Agent 交叉验证：

```powershell
Get-CimInstance -ClassName Win32_UserAccount `
  -Filter "LocalAccount=True AND Name='demo_user'" |
Select-Object Name, Disabled, SID
```

此时 `Disabled` 应为 `True`。重复禁用仍应返回 `success`，并说明原状态已经符合要求。

重新启用：

```text
启用 Agent <AGENT_ID> 上的 demo_user
```

预期返回 `success`，本机查询的 `Disabled` 应恢复为 `False`。演示结束时务必让
`demo_user` 保持启用状态。

## 9. 检查完整回传链路

目标 Agent 的动作日志：

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Tail 50
```

目标 Agent 的结构化结果日志：

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\endpoint-response-query.log" -Tail 20
```

成功事件应包含：

```json
{"event_type":"wazuh_ai_endpoint_response_result","request_id":"...","action":"terminate_process","operation_status":"success","process_closed_at_utc":"2026-08-24T08:30:04.8700000Z"}
```

页面中的“进程处置耗时”使用响应智能体接收任务的时间与 `process_closed_at_utc` 计算，
不包含结果日志进入 Manager 和 Indexer 的等待时间。为保证数值准确，运行后端的主机与
目标 Agent 必须保持系统时间同步。

Manager 检查规则 100211 告警：

```bash
sudo grep 'wazuh_ai_endpoint_response' /var/ossec/logs/alerts/alerts.json | tail -n 10
```

## 10. 状态解释与故障定位

- `success（已验证成功）`：Agent 已执行动作并返回符合预期的实际状态。
- `failed（执行失败）`：目标不存在、不符合白名单、命令执行报错或实际状态未生效。
- `unknown（状态未知）`：命令已经投递，但事件响应智能体在 60 秒内没有从 Indexer 取得对应 `request_id`
  的结果。

出现 `unknown` 时依次检查：

1. `endpoint-response-query.log` 是否生成了相同 `request_id` 的 JSON。
2. Agent 的 `ossec.conf` 是否采集该日志，Wazuh Agent 是否为 `Running`。
3. Manager 的规则 100211 是否命中。
4. 后端是否能直连 `<INDEXER_IP>:9200`；使用隧道时确认 SSH 窗口是否仍在运行。
5. `.env` 中的 Indexer 主机、端口和账号是否仍然正确。
