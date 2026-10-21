# 麒麟服务器 / Linux 开机自启动

这套配置用于将已经能够手动运行的项目交给 systemd 管理，适用于使用 systemd 的麒麟服务器系统。请在虚拟机中执行安装，不是在 Windows 宿主机上执行。先确认 `systemctl --version` 正常输出。

两个服务分别是：

| 服务 | 工作内容 | 监听地址 |
| --- | --- | --- |
| `wazuh-memory` | 智能体执行、对话记忆、报告和知识图谱 API | `127.0.0.1:8001` |
| `wazuh-frontend` | Vite 前端及 Wazuh、Indexer、对话 API 代理 | `0.0.0.0:8112` |

保持当前 Vite 运行方式以保留已经验证的代理和 `.env.development` 配置。远程电脑仅连接虚拟机的 8112。无需启动 `langgraph dev`。这不是 Nginx 静态部署方案，不能直接用 `pnpm preview` 替换前端命令。

## 安装前

1. 在 Linux 虚拟机内安装好依赖并确认前端、后端可以手动运行。Windows 的 `.venv` 和 `node_modules` 不能直接复制到 Linux 使用。
2. 项目根目录应有 `.env`、`.venv/bin/python`，前端目录应有 `.env.development` 和 `node_modules`。安装器不会重新安装依赖，也不会修改配置中的凭据。
3. 使用有权读取项目、执行 Python/Node、写入前端缓存及报告/图谱目录的账号运行服务。通常选择此前手动运行项目的账号。
4. 停止之前手动启动的前端和 8001 进程，避免端口冲突。前端固定使用 8112，端口占用时会报错并重试，不会自动改用 8113。

## 预览和安装

进入虚拟机中的实际项目根目录，路径不需要与 Windows 上相同：

```bash
cd /实际的项目目录/wazuh_ai_agent-master

# 先预览。这里的 user 和 node 都从当前登录环境取得。
python3 deploy/systemd/install.py --user "$(id -un)" --node "$(command -v node)" --dry-run

# 安装到 /etc/systemd/system/，同时启动并启用开机自启动。
sudo python3 deploy/systemd/install.py --user "$(id -un)" --node "$(command -v node)"
```

如果已使用 root 登录且没有 sudo，可以直接执行第二条安装命令而不加 `sudo`；也可用 `--user 用户名` 指定服务账号。安装后使用该账号和项目虚拟环境运行服务，不依赖交互式终端或激活脚本。

如果虚拟环境不叫 `.venv`，增加 `--python /绝对路径/venv/bin/python`。Node.js 安装在 nvm 等用户目录时，也必须保证所选服务账号能访问它。

安装器根据当前位置生成两个服务单元，不需要手工修改模板。运行目录保证后端能找到根目录 `.env`，Vite 能读取前端配置；它直接使用已有虚拟环境和 Node.js，开机不会运行依赖安装或同步命令。

## 验证

```bash
systemctl is-enabled wazuh-memory wazuh-frontend
systemctl status wazuh-memory wazuh-frontend --no-pager
journalctl -u wazuh-memory -u wazuh-frontend -n 100 --no-pager

# 在虚拟机内，验证后端和前端代理均可用。
curl --fail http://127.0.0.1:8001/openapi.json
curl --fail http://127.0.0.1:8112/soc-api/openapi.json
```

等待服务初始化完成，再用其他电脑访问 `http://虚拟机IP:8112` 并测试对话。前端进程启动不代表模型、Wazuh 已可连接。服务启动顺序已安排为后端在前，但不会等待模型和全部业务接口就绪。

如果服务正常而其他电脑无法访问，检查虚拟机网络和 8112 入站规则。系统使用并启用了 firewalld 时，向虚拟机外部网卡所属的 zone 开放 `8112/tcp`；不要为了代理访问而开放 8001。若该网卡位于默认 zone，可执行：

```bash
sudo firewall-cmd --permanent --add-port=8112/tcp
sudo firewall-cmd --reload
```

确认安装正确后可重启虚拟机，验证无需登录即可访问页面和对话。

## 日常操作

```bash
# 实时日志（Ctrl+C 只退出日志查看，不会停止服务）。
sudo journalctl -u wazuh-memory -u wazuh-frontend -f

# 修改后端配置或代码后重启后端；这会清除当前进程中的对话上下文。
sudo systemctl restart wazuh-memory

# 修改前端配置后重启前端。
sudo systemctl restart wazuh-frontend

# 停止并取消开机自启动，恢复手动运行。
sudo systemctl disable --now wazuh-frontend wazuh-memory
```

如果迁移项目目录、虚拟环境或 Node.js 路径，需从新目录重新执行安装器，然后执行 `sudo systemctl restart wazuh-memory wazuh-frontend`。单纯修改 `.env` 无需重新安装服务。

异常退出时 systemd 会在 5 秒后尝试重启；通过 `systemctl stop` 主动停止不会触发这种重启。当前记忆仍存于进程内，服务自动启动和重启不意味着会话已持久化；虚拟机或 8001 重启后需新建会话。
