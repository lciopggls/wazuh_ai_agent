#!/usr/bin/env python3
"""Install a Wazuh collection agent using README chapter 1.3.1."""

import ipaddress
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path


GPG_URL = "https://packages.wazuh.com/key/GPG-KEY-WAZUH"


def run(*args, env=None):
    print("+", " ".join(args), flush=True)
    subprocess.run(args, env=env, check=True)


def ask_manager_ip():
    while True:
        value = input("请输入中心服务端 IP 地址: ").strip()
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            print("IP 地址格式无效，请重新输入。")


def install_apt(manager_ip):
    print("检测到 Debian/Ubuntu 软件包管理器。")
    run("apt-get", "install", "-y", "gnupg", "apt-transport-https")
    with urllib.request.urlopen(GPG_URL, timeout=60) as response:
        key = response.read()
    keyring = Path("/usr/share/keyrings/wazuh.gpg")
    if keyring.exists():
        keyring.unlink()
    print("+ 导入 Wazuh 软件包签名密钥", flush=True)
    subprocess.run(
        ["gpg", "--batch", "--no-default-keyring",
         f"--keyring=gnupg-ring:{keyring}", "--import"],
        input=key, check=True,
    )
    keyring.chmod(0o644)
    Path("/etc/apt/sources.list.d/wazuh.list").write_text(
        "deb [signed-by=/usr/share/keyrings/wazuh.gpg] "
        "https://packages.wazuh.com/4.x/apt/ stable main\n",
        encoding="utf-8",
    )
    run("apt-get", "update")
    run("apt-get", "install", "-y", "wazuh-agent",
        env={**os.environ, "WAZUH_MANAGER": manager_ip})


def install_rpm(manager_ip):
    manager = shutil.which("dnf") or shutil.which("yum")
    if manager is None:
        raise RuntimeError("未找到 dnf 或 yum。")
    print(f"检测到 RPM 软件包管理器：{Path(manager).name}。")
    run("rpm", "--import", GPG_URL)
    Path("/etc/yum.repos.d/wazuh.repo").write_text(
        "[wazuh]\n"
        "gpgcheck=1\n"
        "gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\n"
        "enabled=1\n"
        "name=EL-$releasever - Wazuh\n"
        "baseurl=https://packages.wazuh.com/4.x/yum/\n"
        "priority=1\n",
        encoding="utf-8",
    )
    run(manager, "install", "-y", "wazuh-agent",
        env={**os.environ, "WAZUH_MANAGER": manager_ip})


def main():
    if sys.platform != "linux":
        raise RuntimeError("此脚本仅适用于 Linux。")
    if os.geteuid() != 0:
        raise RuntimeError("请使用 sudo python3 setup_wazuh_agent_linux.py 运行。")
    manager_ip = ask_manager_ip()
    if shutil.which("apt-get"):
        install_apt(manager_ip)
    elif shutil.which("rpm") and (shutil.which("dnf") or shutil.which("yum")):
        install_rpm(manager_ip)
    else:
        raise RuntimeError("不支持当前系统的软件包管理器。")
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "wazuh-agent")
    run("systemctl", "start", "wazuh-agent")
    run("systemctl", "is-active", "--quiet", "wazuh-agent")
    print("Wazuh Linux 采集客户端已安装并启动。")


if __name__ == "__main__":
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print("\n已取消。", file=sys.stderr)
        sys.exit(1)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        sys.exit(1)
