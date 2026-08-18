# Agent 001 IP 封禁查询验证部署

查询验证链路使用 Wazuh 原生通信：AI 发送 Active Response 查询请求，Windows Agent
查询真实防火墙规则并写出专用 JSON 日志，Manager 将日志转换为告警，AI 再按唯一
`request_id` 从 Indexer 取回结果。

## 1. 更新 Agent 001 脚本

在 Agent 001 的管理员 PowerShell 中，把项目中的新版 `block-ip.ps1` 复制到：

```text
C:\Program Files (x86)\ossec-agent\active-response\bin\block-ip.ps1
```

`block-ip.bat` 保持不变。新版 PowerShell 脚本只查询名称以
`Wazuh_AI_Block_` 开头的规则。

## 2. 配置 Agent 001 收集查询日志

打开：

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

将 `windows-agent-query.xml` 中的完整 `<ossec_config>` 块追加到文件末尾。然后创建空日志
并重启 Agent：

```powershell
$queryLog = "C:\Program Files (x86)\ossec-agent\active-response\block-ip-query.log"
if (-not (Test-Path $queryLog)) {
    New-Item -ItemType File -Path $queryLog -Force
}

Restart-Service -Name wazuh
Start-Sleep -Seconds 20
Get-Service -Name wazuh
```

## 3. 在 Manager 安装查询告警规则

把 `manager-query-rule.xml` 复制到 Ubuntu Manager：

```text
/var/ossec/etc/rules/wazuh_ai_block_query.xml
```

然后执行：

```bash
sudo chown wazuh:wazuh /var/ossec/etc/rules/wazuh_ai_block_query.xml
sudo chmod 660 /var/ossec/etc/rules/wazuh_ai_block_query.xml
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager
```

规则 ID 为 `100210`。开始部署前已通过当前 Wazuh API 确认该 ID 未被占用。

可以用以下单行 JSON 运行 `wazuh-logtest`，预期命中规则 `100210`：

```json
{"event_type":"wazuh_ai_block_query_complete","request_id":"00000000-0000-0000-0000-000000000001","target_ip":"203.0.113.10","query_status":"ok","rule_count":0}
```

## 4. 建立 Windows 后端到 Indexer 的安全连接

当前环境访问 Manager 的 `55000` 成功，但访问 `192.168.28.131:9200` 被拒绝。验证阶段推荐
使用 SSH 本地转发，不要直接把 Indexer 端口暴露给整个网络。

在单独的 Windows PowerShell 窗口运行，并保持窗口开启：

```powershell
ssh -N -L 127.0.0.1:19200:127.0.0.1:9200 <Ubuntu用户名>@192.168.28.131
```

然后在项目 `.env` 中设置：

```dotenv
WAZUH_INDEXER_HOST="127.0.0.1"
WAZUH_INDEXER_PORT="19200"
```

使用 Indexer 用户进行只读连接测试，命令会提示输入密码：

```powershell
curl.exe -k -u admin https://127.0.0.1:19200
```

## 5. 重启 demo_agent

停止旧的 `langgraph dev`，重新启动：

```powershell
$env:UV_CACHE_DIR = "$PWD\.uv-cache"
uv run langgraph dev
```

在页面选择 `demo_agent` 并创建新线程。

## 6. 验证顺序

先查询一个未封禁 IP：

```text
查询 Agent 001 是否封禁了 203.0.113.10
```

预期为 `verified_unblocked`。然后执行：

```text
在 Agent 001 上双向封禁 203.0.113.10，持续10分钟
```

封禁工具会自动查询并验证，预期为 `verified_blocked`，且证据中同时出现入站和出站规则。

再次主动查询：

```text
查询 Agent 001 当前所有由 Wazuh AI 管理的 IP 封禁规则
```

最后手动解封：

```text
在 Agent 001 上解除对 203.0.113.10 的封禁
```

预期为 `verified_unblocked`。

## 7. 故障定位

Agent 没有生成 JSON：

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Tail 100
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\block-ip-query.log" -Tail 20
```

Manager 没有生成规则 100210 告警：

```bash
sudo tail -n 200 /var/ossec/logs/ossec.log | grep -Ei "100210|block.query|json|error"
```

结果为 `unknown`：依次检查 Agent 专用日志、Manager 规则、SSH 隧道和 Indexer 查询。
