"""Install the Wazuh Windows collection agent using README chapter 1.3.2."""

import ctypes
import ipaddress
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


MSI_URL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi"


def ask_manager_ip():
    while True:
        value = input("请输入中心服务端 IP 地址: ").strip()
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            print("IP 地址格式无效，请重新输入。")


def run(*args, accepted=(0,)):
    print("+", " ".join(map(str, args)), flush=True)
    result = subprocess.run(args, check=False)
    if result.returncode not in accepted:
        raise RuntimeError(f"命令失败，退出代码 {result.returncode}")


def main():
    if sys.platform != "win32":
        raise RuntimeError("此脚本仅适用于 Windows。")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("请以管理员身份打开 PowerShell 后运行此脚本。")
    manager_ip = ask_manager_ip()
    with tempfile.TemporaryDirectory(prefix="wazuh-agent-") as temporary:
        msi = Path(temporary) / "wazuh-agent-4.14.7-1.msi"
        print(f"正在下载 {MSI_URL}", flush=True)
        urllib.request.urlretrieve(MSI_URL, msi)
        run("msiexec.exe", "/i", str(msi), "/qn", "/norestart",
            f"WAZUH_MANAGER={manager_ip}", accepted=(0, 3010))
    service = subprocess.run(["sc.exe", "query", "wazuhsvc"],
                             capture_output=True, text=True, check=True)
    if "RUNNING" not in service.stdout:
        run("sc.exe", "start", "wazuhsvc")
    print("Wazuh Windows 采集客户端已安装并启动。")


if __name__ == "__main__":
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print("\n已取消。", file=sys.stderr)
        sys.exit(1)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        sys.exit(1)
