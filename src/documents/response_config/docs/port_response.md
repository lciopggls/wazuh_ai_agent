# Windows Agent 入站 TCP 54321 封禁部署与验证

完整环境、Manager、Indexer 和后端部署顺序见 [主部署文档](../README.md)。本文保留端口
响应的完整配置、限制和专项验证步骤。

该功能只用于展示，固定限制如下：

- 支持任意有效的数字 Agent ID，但每个目标 Agent 都必须部署脚本和日志采集配置。
- 只能操作入站 TCP 54321。
- 封禁时长只能是 30、60、300 秒，默认 30 秒。
- 支持封禁、手动解封和查询真实 Windows 防火墙状态。
- 结果状态只有 `blocked（已封禁）`、`unblocked（未封禁）`、
  `unknown（状态未知）`。
- 事件响应智能体最长等待 60 秒取得真实状态；该等待时间不是端口封禁时长。

现有 IP 封禁脚本无需修改。

## 1. 向目标 Windows Agent 部署脚本

把以下文件复制到：

```text
C:\Program Files (x86)\ossec-agent\active-response\bin\
```

文件：

```text
../windows_agent/scripts/block-port.bat
../windows_agent/scripts/block-port.ps1
```

管理员 PowerShell 检查：

```powershell
$bin = "C:\Program Files (x86)\ossec-agent\active-response\bin"
Get-Item "$bin\block-port.bat", "$bin\block-port.ps1"
```

## 2. 配置 Windows Agent 查询日志采集

打开：

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

把 `../windows_agent/log_collection/windows-agent-port-query.xml` 中的完整
`<ossec_config>` 块追加到文件末尾：

```xml
<ossec_config>
  <localfile>
    <location>C:\Program Files (x86)\ossec-agent\active-response\block-port-query.log</location>
    <log_format>json</log_format>
    <only-future-events>yes</only-future-events>
    <label key="@source">demo-port-query</label>
  </localfile>
</ossec_config>
```

创建空日志文件并重启 Agent：

```powershell
$queryLog = "C:\Program Files (x86)\ossec-agent\active-response\block-port-query.log"
if (-not (Test-Path $queryLog)) {
    New-Item -ItemType File -Path $queryLog -Force
}

Restart-Service -Name wazuh
Start-Sleep -Seconds 15
Get-Service -Name wazuh
```

预期服务状态为 `Running`。

## 3. 配置 Ubuntu Manager Active Response

在 `/var/ossec/etc/ossec.conf` 的 Active Response 区域添加：

同一完整片段位于 `../wazuh_manager/active_response/ossec_ar_fix.xml`。

```xml
<command>
  <name>block-port</name>
  <executable>block-port.bat</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

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

后端分别调用 `block-port30`、`block-port60`、`block-port300` 和 `block-port0`。

## 4. 安装 Manager 查询规则

复制规则：

```bash
sudo cp /tmp/manager-port-query-rule.xml /var/ossec/etc/rules/demo_port_query.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/demo_port_query.xml
sudo chmod 660 /var/ossec/etc/rules/demo_port_query.xml
sudo /var/ossec/bin/wazuh-analysisd -t
```

配置检查通过后重启：

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager
```

该规则使用 ID `100212`。如果环境中已占用该 ID，应换成未占用的自定义规则 ID。

## 5. 准备可连接的测试服务

在目标 Windows Agent 的管理员 PowerShell 中创建临时允许规则：

```powershell
New-NetFirewallRule `
  -DisplayName "Demo_Allow_In_TCP_54321" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalPort 54321
```

随后启动临时 HTTP 服务：

```powershell
python -m http.server 54321 --bind 0.0.0.0
```

保持窗口运行。在 Ubuntu 虚拟机中先验证封禁前能够连接：

```bash
curl --connect-timeout 3 http://<AGENT_IP>:54321
```

预期返回目录页面。如果失败，先确认目标 Agent 的实际 IP、虚拟机网络模式、Python 服务和
临时允许规则，不要进入页面封禁测试。

## 6. 启动后端

在项目根目录停止旧进程后重新启动：

```powershell
$env:UV_CACHE_DIR = "$PWD\.uv-cache"
uv run langgraph dev
```

在页面选择 `router_agent` 并新建对话。正常验证由总控路由到事件响应智能体；只有路由
排错时才直接进入 `response_agent`。

## 7. 页面完整验证

先查询：

```text
查询 Agent <AGENT_ID> 的 54321 端口是否被封禁
```

预期为 `unblocked（未封禁）`。

封禁 30 秒：

```text
在 Agent <AGENT_ID> 上封禁 54321 端口
```

未指定时长时默认 30 秒。预期为 `blocked（已封禁）`，并显示入站 TCP 54321 的真实规则
证据。

立即在 Ubuntu 再次测试：

```bash
curl --connect-timeout 3 http://<AGENT_IP>:54321
```

预期连接超时或失败。等待 35 秒后再次执行同一命令，预期恢复成功。

验证其他允许时长：

```text
在 Agent <AGENT_ID> 上封禁 54321 端口 60 秒
在 Agent <AGENT_ID> 上封禁 54321 端口 300 秒
```

验证手动解封：

```text
解除 Agent <AGENT_ID> 上 54321 端口的封禁
```

预期为 `unblocked（未封禁）`。手动解封后应等待原封禁时长结束，再进行下一次封禁测试。

验证越权拒绝：

```text
在 Agent <AGENT_ID> 上封禁 54322 端口 30 秒
在 Agent <AGENT_ID> 上封禁 54321 端口 45 秒
```

两次都应返回拒绝原因和允许范围，且不会向 Agent 发送执行命令。使用其他有效 Agent ID
不再属于越权请求，但该 Agent 必须已部署本功能。

## 8. 排错与清理

Windows 查看脚本日志和查询日志：

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Tail 50
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\block-port-query.log" -Tail 50
Get-NetFirewallRule -DisplayName "Demo_Block_In_TCP_54321" -ErrorAction SilentlyContinue
```

演示结束后删除临时允许规则：

```powershell
Remove-NetFirewallRule -DisplayName "Demo_Allow_In_TCP_54321" -ErrorAction SilentlyContinue
```

在 HTTP 服务窗口按 `Ctrl+C` 停止临时服务。端口阻断规则正常情况下会自动删除；也可以先在
页面执行手动解封。
