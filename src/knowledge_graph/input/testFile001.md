- ### 攻击溯源调查报告

  #### 事件概览

  本次事件为一起针对主机 Agent 005 (用户 defin) 的复杂无文件攻击。攻击者通过 rundll32.exe 调用 url.dll 加载恶意 HTA 文件，随后执行了包括防御削弱、网络侦察、载荷混淆及多重持久化在内的一系列恶意行为。攻击全程采用了“离地攻击（LotL）”技术，最终通过修改注册表和创建计划任务实现了隐蔽持久化，并尝试向远程服务器发起下一阶段载荷的拉取请求。

  #### 攻击痕迹与来源分析

  **失陷主机：** DESKTOP-NR6HCQ3 (Agent 005) **初始攻击入口：** 用户执行(T1204)恶意 HTA 文件 `C:\noa\advanced_fileless_c2_chain.hta`，该文件由 `rundll32.exe` 调用 `url.dll,OpenURL` 加载。

  **恶意文件/载荷：**

  - `C:\noa\advanced_fileless_c2_chain.hta`：初始阶段载荷，负责建立攻击链。
  - *注：本次攻击链中未发现落地自定义恶意二进制可执行文件，全程依赖系统原生组件。*

  **被利用/篡改的进程：**

  - `rundll32.exe` (PID: 9352)：被用于执行恶意 HTA 文件，规避对 `mshta.exe` 的直接检测。
  - `mshta.exe` (PID: 9248)：被用于加载恶意 HTA 脚本并执行后续命令。
  - `cmd.exe` (PID: 5516)：被 `mshta.exe` 派生，作为后续攻击任务的并行执行器。
  - `powershell.exe` (PID: 8788, PID: 8890)：被用于执行关闭防火墙的命令及发起 C2 网络请求。
  - `ipconfig.exe` (PID: 8256)：被用于进行网络环境侦察。
  - `reg.exe` (PID: 6488)：被用于写入注册表以实现持久化。
  - `schtasks.exe` (PID: 4828)：被用于创建计划任务以触发注册表中的载荷。

  **网络指标：**

  - **C2 服务器 IP / URL：** `http://203.0.113.100:8080/stage_complete`：用于在环境准备（防火墙关闭）完毕后，静默发起下一阶段的网络回连请求。

  #### 进程执行树

  根据完全因果链分析，可验证的进程执行树如下：

  Plaintext

  ```
  └── PID 9352 (rundll32.exe) @ 2026-06-26 15:26:58.634
      └── PID 9248 (mshta.exe) @ 2026-06-26 15:26:59.700
          ├── PID 5516 (cmd.exe) @ 2026-06-26 15:26:59.701
          │   ├── PID 8788 (powershell.exe) @ 2026-06-26 15:26:59.701 [L1_FW: 关闭防火墙]
          │   ├── PID 8256 (ipconfig.exe) @ 2026-06-26 15:26:59.701  [L1_Recon: 网络侦察]
          │   └── PID 6488 (reg.exe) @ 2026-06-26 15:26:59.701       [L1_Reg: 写入注册表]
          ├── PID 4828 (schtasks.exe) @ 2026-06-26 15:27:01.996      [L2: 埋设计划任务]
          └── PID 8890 (powershell.exe) @ 2026-06-26 15:27:03.012    [L3: 发起 C2 回连]
  ```

  #### 攻击时间线与执行流程

  - **[2026-06-26 15:26:58.634] - [执行 / T1204]：** `C:\Windows\System32\rundll32.exe` (PID: 9352) 以命令行 `rundll32.exe url.dll,OpenURL C:\noa\advanced_fileless_c2_chain.hta` 启动，通过调用 `url.dll` 间接加载并执行了恶意 HTA 文件。
  - **[2026-06-26 15:26:59.700] - [执行 / T1059.003]：** `C:\Windows\SysWOW64\mshta.exe` (PID: 9248) 被 `rundll32.exe` 创建，确认其加载了该恶意 HTA 脚本。随后，`mshta.exe` 派生了 `cmd.exe`，以此为跳板并行触发层级 1 (Layer 1) 的各项动作。
  - **[2026-06-26 15:26:59.701] - [防御规避 / T1562.004]：** `cmd.exe` 通过 `start /B` 并行启动了 `powershell.exe` (PID: 8788)，执行命令 `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False` 以关闭系统防火墙。
  - **[2026-06-26 15:26:59.701] - [发现 / T1016]：** 同时，启动了 `ipconfig.exe` (PID: 8256) 以及系统路由查询，并将网络配置信息重定向输出到 `C:\Users\Public\net_recon.txt`。
  - **[2026-06-26 15:26:59.701] - [持久化 / T1112, T1027]：** 此外，启动了 `reg.exe` (PID: 6488)，向注册表项 `HKCU\SOFTWARE\SystemUpdate` 写入了一个 Base64 编码的值 (`cGluZyAxMjcuMC4wLjE=`)。
  - **[2026-06-26 15:27:01.996] - [持久化 / T1053.005]：** 经过层级间的逻辑延时后，`mshta.exe` 创建了子进程 `schtasks.exe` (PID: 4828)，命令行为 `/Create /F /TN "SysUpdate_Task" ...`。此举创建了计划任务，确保每次用户登录时都会解码并执行注册表中的恶意 PowerShell 载荷。
  - **[2026-06-26 15:27:03.012] - [命令与控制 / T1071.001]：** 计划任务埋设完毕后，脚本触发层级 3 (Layer 3) 逻辑，再次启动 `powershell.exe` (PID: 8890) 执行 `Invoke-WebRequest`，向 `http://203.0.113.100:8080/stage_complete` 发送请求，标志当前攻击链阶段完成。

  #### 总结与建议

  **使用的工具：** 被滥用的合法系统工具：`rundll32.exe`, `mshta.exe`, `cmd.exe`, `powershell.exe`, `reg.exe`, `ipconfig.exe`, `schtasks.exe`。攻击者全程使用了“离地攻击”技术，未在攻击链初期引入任何自定义恶意二进制文件。

  **恶意载荷：** 本次事件为纯粹的无文件攻击前置阶段，恶意逻辑被拆解并分布于 HTA 脚本、系统注册表及计划任务中。

  **网络行为：** 确认受害主机向 IP 地址 `203.0.113.100` 的 8080 端口发起了 HTTP 请求，该行为发生于本地防火墙被强制关闭之后，疑似用于报告感染状态或拉取后续载荷。

  **横向移动/数据外泄：** 在当前日志时间窗口内，未发现直接的横向移动或高权限凭证窃取证据。网络侦察结果留存在本地公共目录下，尚未观察到外发行为。

  **用户活动：** 用户 DESKTOP-NR6HCQ3\defin 通过 `rundll32.exe` 触发了位于 `C:\noa\advanced_fileless_c2_chain.hta` 的恶意脚本，推测为遭受社会工程学攻击的初始失陷点。

  **关键结论与建议：**

  1. **清除持久化机制：** 立即删除名为 `SysUpdate_Task` 的计划任务，并清理恶意注册表项 `HKCU\SOFTWARE\SystemUpdate`。
  2. **恢复系统防御：** 重新启用 Windows 防火墙 (Domain, Public, Private 配置文件)。
  3. **封禁 IOC：** 在网络层防火墙上封禁 IP 地址 `203.0.113.100` 的出站流量。
  4. **清理侦察痕迹：** 删除被用作信息暂存的 `C:\Users\Public\net_recon.txt` 文件。
  5. **排查初始入口：** 深入排查用户 defin 的邮件收发记录、浏览器下载历史及近期打开的文件，确认 `advanced_fileless_c2_chain.hta` 的初始投递途径。
  6. **加强终端规则：** 强化对 `mshta.exe` 派生 `powershell.exe` 以及利用 `reg.exe` 配合 `schtasks.exe` 建立无文件持久化的行为基线监控，优化事件聚合逻辑以减少噪音干扰。