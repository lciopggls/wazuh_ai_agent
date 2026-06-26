# Active Response 配置说明

事件响应智能体通过 Wazuh Active Response 机制在指定 Agent 上执行 IP 封禁。使用前需要在 Wazuh Manager 所在主机完成以下配置。

## 前置条件

- 具备 Wazuh Manager 所在主机的 root 权限
- Wazuh Agent 上已部署 `netsh` active-response 脚本（这一步安装wazuh时默认配置好了）

## 配置步骤

### 1. 修改 ossec.conf

编辑 Wazuh Manager 的 `/var/ossec/etc/ossec.conf`，在 `<ossec_config>` 内找到 `<!-- Active response -->` 相关段落，添加以下四个 active-response 配置块：

```xml
<active-response>
    <command>netsh</command>
    <location>local</location>
    <rules_id>999991</rules_id>
    <timeout>600</timeout>
</active-response>

<active-response>
    <command>netsh</command>
    <location>local</location>
    <rules_id>999992</rules_id>
    <timeout>3600</timeout>
</active-response>

<active-response>
    <command>netsh</command>
    <location>local</location>
    <rules_id>999993</rules_id>
    <timeout>86400</timeout>
</active-response>

<active-response>
    <command>netsh</command>
    <location>local</location>
    <rules_id>999994</rules_id>
</active-response>
```

| rules_id | 对应命令 | 封禁时长 | timeout（秒） |
|----------|----------|----------|--------------|
| 999991 | netsh600 | 10 分钟 | 600 |
| 999992 | netsh3600 | 1 小时 | 3600 |
| 999993 | netsh86400 | 1 天 | 86400 |
| 999994 | netsh0 | 永久 | 无（不自动解除） |

### 2. 重启 Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
```

重启后配置生效，事件响应智能体即可通过 Wazuh API 在指定 Agent 上执行 IP 封禁。
