# Windows IP 封禁 Active Response 部署说明

事件响应智能体使用同一套 `block-ip` 脚本完成定时封禁、永久封禁、手动解封和规则记录。实现遵循 Wazuh 4.x Active Response 协议：Agent 通过 stdin 向脚本发送 JSON，定时封禁通过 `check_keys`/`continue` 握手去重，并在超时后用 `delete` 命令撤销。

完整环境、Manager、Indexer 和后端部署顺序见 [主部署文档](../README.md)。本文只补充 IP
响应的协议、查询链路和专项验证。

官方协议说明：

- <https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html>
- <https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/commands.html>

## 1. 在 Windows Agent 部署脚本

将以下两个文件复制到每台需要执行封禁的 Windows Agent：

```text
C:\Program Files (x86)\ossec-agent\active-response\bin\block-ip.bat
C:\Program Files (x86)\ossec-agent\active-response\bin\block-ip.ps1
```

仓库中的源文件：

- `../windows_agent/scripts/block-ip.bat`
- `../windows_agent/scripts/block-ip.ps1`

脚本必须部署在 Agent，不是 Wazuh Manager 的 `/var/ossec/active-response/bin`。Windows Agent 的 `wazuh-execd` 会以 Active Response JSON 协议调用 BAT，BAT 再启动 PowerShell 实现。

部署后重启 Agent：

```powershell
Restart-Service -Name wazuh
```

## 2. 在 Manager 注册命令

编辑 Wazuh Manager 的 `/var/ossec/etc/ossec.conf`，在 `<ossec_config>` 内加入以下命令定义：

```xml
<command>
  <name>block-ip</name>
  <executable>block-ip.bat</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

然后把四个超时变体都绑定到 `block-ip`。项目中的
`../wazuh_manager/active_response/ossec_ar_fix.xml` 包含可直接核对的完整片段。

```xml
<active-response>
  <command>block-ip</command>
  <location>local</location>
  <rules_id>999991</rules_id>
  <timeout>600</timeout>
</active-response>

<active-response>
  <command>block-ip</command>
  <location>local</location>
  <rules_id>999992</rules_id>
  <timeout>3600</timeout>
</active-response>

<active-response>
  <command>block-ip</command>
  <location>local</location>
  <rules_id>999993</rules_id>
  <timeout>86400</timeout>
</active-response>

<active-response>
  <command>block-ip</command>
  <location>local</location>
  <rules_id>999994</rules_id>
</active-response>
```

这些 rule ID 必须与本地规则文件中的预留规则一致。若只通过 API 手动触发，也仍要保留四个 Active Response 块，以注册下表中的命令标识。

| API 命令标识 | 时长 | 超时动作 |
|---|---:|---|
| `block-ip600` | 10 分钟 | 自动发送 `delete` |
| `block-ip3600` | 1 小时 | 自动发送 `delete` |
| `block-ip86400` | 1 天 | 自动发送 `delete` |
| `block-ip0` | 永久 | 不自动解除 |

修改后先验证配置，再重启 Manager：

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

## 3. API 负载约定

Python 端向 `PUT /active-response?agents_list=<agent_id>` 发送：

```json
{
  "command": "block-ip600",
  "arguments": [],
  "alert": {
    "data": {
      "action": "block",
      "srcip": "192.0.2.10"
    }
  }
}
```

方向字段与防火墙规则的对应关系：

| 请求方向 | alert.data | Windows Firewall |
|---|---|---|
| `srcip` | 仅 `srcip` | 入站 `remoteip` 阻断 |
| `dstip` | 仅 `dstip` | 出站 `remoteip` 阻断 |
| `both` | 同时包含两者 | 入站和出站各一条规则 |

手动解封复用 `block-ip0`，并发送 `action=unblock`。脚本会删除目标 IP 对应的入站和出站规则，不需要 `netsh-unblock` 脚本。

查询当前受管规则同样复用 `block-ip0`，并发送 `action=list`、唯一 `request_id` 和可选
`target_ip`。脚本查询真实的 Windows Firewall 状态，并把逐规则事件和完成事件写入：

```text
C:\Program Files (x86)\ossec-agent\active-response\block-ip-query.log
```

`../windows_agent/log_collection/windows-agent-query.xml` 中的 `<localfile>` 配置将单行
JSON 发送给 Manager，`../wazuh_manager/rules/manager-query-rule.xml` 中的规则将其转换为
可在 `wazuh-alerts-*` 查询的低等级告警。后端按 `request_id` 每秒轮询一次。通过事件响应
智能体调用时最多等待 60 秒；直接调用底层 Server API 且未覆盖参数时默认等待 30 秒。

Wazuh Active Response API 只确认命令是否已投递到 Agent，不会把脚本 stdout 或防火墙
执行结果同步返回。因此，API 返回 `error: 0` 表示“命令已发送”，不能单独视为“防火墙
已经生效”。本项目只有在查询结果为 `verified_blocked` 或 `verified_unblocked` 时才汇报
“已验证成功”。

### 3.1 Windows Agent 查询日志配置

将 `../windows_agent/log_collection/windows-agent-query.xml` 中的完整 `<ossec_config>` 块
加入 Agent 的：

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

配置后重启 Windows Wazuh Agent。

### 3.2 Manager 查询告警规则

将 `../wazuh_manager/rules/manager-query-rule.xml` 复制到 Manager：

```text
/var/ossec/etc/rules/wazuh_ai_block_query.xml
```

然后执行：

```bash
sudo chown wazuh:wazuh /var/ossec/etc/rules/wazuh_ai_block_query.xml
sudo chmod 660 /var/ossec/etc/rules/wazuh_ai_block_query.xml
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

该规则默认使用 ID `100210`。如果目标环境已经占用该 ID，应改成未占用的自定义规则 ID。
可将以下单行 JSON 输入 `wazuh-logtest`，预期命中规则 `100210`：

```json
{"event_type":"wazuh_ai_block_query_complete","request_id":"00000000-0000-0000-0000-000000000001","target_ip":"203.0.113.10","query_status":"ok","rule_count":0}
```

### 3.3 Indexer 连接

默认让后端直接连接 `<INDEXER_IP>:9200`。先从后端主机验证：

```powershell
Test-NetConnection <INDEXER_IP> -Port 9200
curl.exe -k -u <INDEXER_USER> https://<INDEXER_IP>:9200
```

直连失败或安全策略禁止开放 9200 时，再按照主部署文档使用本地 SSH 隧道。

## 4. 验证方法

在 LangGraph 页面选择 `router_agent` 并创建新对话。将 `<AGENT_ID>` 替换为实际数字 ID，
依次执行：

```text
查询 Agent <AGENT_ID> 是否封禁了 203.0.113.10
在 Agent <AGENT_ID> 上双向封禁 203.0.113.10，持续 10 分钟
查询 Agent <AGENT_ID> 当前所有由 Wazuh AI 管理的 IP 封禁规则
在 Agent <AGENT_ID> 上解除对 203.0.113.10 的封禁
```

预期依次得到未封禁、已验证封禁、包含真实规则的查询结果和已验证解封。

发送测试命令后，在目标 Agent 上检查日志：

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Tail 50
```

检查项目脚本创建的规则：

```powershell
netsh advfirewall firewall show rule name=all | Select-String "Wazuh_AI_Block_"
```

规则名前缀如下：

```text
Wazuh_AI_Block_In_<IP>
Wazuh_AI_Block_Out_<IP>
```

定时封禁还应在超时后看到 `Block removed` 日志，并确认相应规则已删除。

检查结构化查询事件：

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\block-ip-query.log" -Tail 20
```

查询结果状态包括 `verified_blocked`、`verified_unblocked`、`partial`、`not_applied`
和 `unknown`，并同时返回中文解释和后续建议。

## 5. 常见故障

- Manager 返回命令不存在：确认 Active Response 块的 `<command>` 是 `block-ip`，而不是 `netsh`。
- Agent 日志提示缺少 `parameters.alert`：部署的仍是旧脚本，重新复制本仓库的 BAT 和 PowerShell 文件。
- API 成功但没有防火墙规则：检查 Agent 的 `active-responses.log`；脚本会记录 `netsh` 的输出和退出码。
- 定时规则不会自动解除：确认 `<timeout_allowed>yes</timeout_allowed>`、对应 `<timeout>` 和 `check_keys` 握手均已配置。
- 只有入站规则：确认调用方向不是 `srcip`；`dstip` 创建出站规则，`both` 才会同时创建两条。
- 查询返回 `unknown`：检查 Agent 是否采集 `block-ip-query.log`、Manager 规则 100210 是否命中，以及 Indexer 中是否存在相同 `request_id` 的告警。
- 直连 Indexer 失败：检查 `<INDEXER_IP>:9200` 的防火墙放行范围和 TLS 服务；如果
  `curl` 返回 `Unauthorized`，说明网络已连通，应检查账号和密码。
