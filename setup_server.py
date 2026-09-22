#!/usr/bin/env python3
"""Automate README chapter 1.2 Wazuh single-node server setup."""
import argparse
import os
import pwd
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

INSTALL_URL = "https://packages.wazuh.com/4.14/wazuh-install.sh"
PASSWORD_MEMBER = "wazuh-install-files/wazuh-passwords.txt"


def run(*args, cwd=None):
    print("+", " ".join(map(str, args)), flush=True)
    subprocess.run(args, cwd=cwd, check=True)


def save_config(path, content):
    old = path.read_text(encoding="utf-8")
    if content == old:
        print(f"Already configured: {path}")
        return
    backup = path.with_name(path.name + ".before-wazuh-automation")
    if not backup.exists():
        shutil.copy2(path, backup)
    path.write_text(content, encoding="utf-8")
    print(f"Updated {path}; backup: {backup}")


def set_logall_json(path):
    source = path.read_text(encoding="utf-8")
    sections = list(re.finditer(r"<global\b[^>]*>(.*?)</global>", source, re.S))
    if len(sections) != 1:
        raise RuntimeError(f"Expected one <global> block in {path}; found {len(sections)}")
    match = sections[0]
    body = match.group(1)
    tags = list(re.finditer(r"<logall_json>\s*.*?\s*</logall_json>", body, re.S))
    if len(tags) > 1:
        raise RuntimeError(f"Multiple logall_json values in {path}")
    if tags:
        body = re.sub(r"<logall_json>\s*.*?\s*</logall_json>",
                      "<logall_json>yes</logall_json>", body, count=1, flags=re.S)
    else:
        body += "\n    <logall_json>yes</logall_json>\n"
    save_config(path, source[:match.start(1)] + body + source[match.end(1):])


def set_filebeat_archives(path):
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines)
              if re.match(r"^filebeat\.modules:\s*(?:#.*)?$", line.rstrip("\r\n"))]
    if len(starts) != 1:
        raise RuntimeError(f"Expected one filebeat.modules block in {path}; found {len(starts)}")
    start = starts[0]
    end = next((i for i in range(start + 1, len(lines))
                if re.match(r"^[A-Za-z_][\w.-]*:\s*", lines[i])), len(lines))
    block = "".join(lines[start:end])
    module = re.search(r"(?m)^([ \t]*)-[ \t]*module:[ \t]*wazuh[ \t]*(?:#.*)?$", block)
    if not module:
        raise RuntimeError(f"No Wazuh module in {path}")
    indent = module.group(1)
    following = block[module.end():]
    next_module = re.search(r"(?m)^" + re.escape(indent) + r"-[ \t]*module:", following)
    stop = module.end() + next_module.start() if next_module else len(block)
    section = block[module.start():stop]
    for key in ("alerts", "archives"):
        pattern = rf"(?m)^([ \t]*){key}:\s*(?:#.*)?\n([ \t]*)enabled:\s*(?:true|false)\b[^\n]*(?:\n|$)"
        matches = list(re.finditer(pattern, section))
        if len(matches) > 1:
            raise RuntimeError(f"Multiple {key}.enabled values in Wazuh module")
        if matches:
            m = matches[0]
            section = section[:m.start()] + f"{m.group(1)}{key}:\n{m.group(2)}enabled: true\n" + section[m.end():]
        else:
            section = section.rstrip("\n") + f"\n{indent}    {key}:\n{indent}      enabled: true\n"
    block = block[:module.start()] + section + block[stop:]
    save_config(path, "".join(lines[:start]) + block + "".join(lines[end:]))


def passwords(archive):
    with tarfile.open(archive, "r:*") as tar:
        member = tar.getmember(PASSWORD_MEMBER)
        stream = tar.extractfile(member)
        if stream is None:
            raise RuntimeError("Password file is missing from archive")
        content = stream.read().decode("utf-8")
    found = {}
    for user in ("wazuh", "admin"):
        patterns = [
            rf"(?im)^\s*The password for user\s+{user}\s+is\s+(.+?)\s*$",
            rf"(?im)^\s*{user}\s*:\s*(\S+)\s*$",
        ]
        matches = [m.group(1).strip() for pattern in patterns for m in re.finditer(pattern, content)]
        if len(matches) != 1:
            raise RuntimeError(f"Could not uniquely identify {user} password; inspect {archive} manually")
        found[user] = matches[0]
    return found


def desktop_for_invoking_user(override):
    if override:
        return Path(override).expanduser()
    username = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
    home = Path(pwd.getpwnam(username).pw_dir)
    config = home / ".config/user-dirs.dirs"
    if config.exists():
        match = re.search(r'^XDG_DESKTOP_DIR="([^"]+)"', config.read_text(encoding="utf-8"), re.M)
        if match:
            return Path(match.group(1).replace("$HOME", str(home)))
    return home / "Desktop"


def write_passwords(target, found):
    uid = pwd.getpwnam(os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name).pw_uid
    gid = pwd.getpwuid(uid).pw_gid
    desktop_existed = target.parent.exists()
    target.parent.mkdir(parents=True, exist_ok=True)
    if not desktop_existed and os.environ.get("SUDO_USER"):
        os.chown(target.parent, uid, gid)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write("Wazuh server credentials\n")
            out.write(f"Server API user: wazuh\nServer API password: {found['wazuh']}\n")
            out.write(f"Indexer user: admin\nIndexer password: {found['admin']}\n")
        os.chmod(target, 0o600)
        os.chown(target, uid, gid)
    except Exception:
        raise
    print(f"Credentials saved to {target} (mode 600)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, default=Path.cwd(), help="Directory for installer and its output archive")
    parser.add_argument("--desktop", type=Path, help="Desktop directory for credentials file")
    parser.add_argument("--skip-install", action="store_true", help="Use existing wazuh-install-files.tar")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run with sudo or as root")
    workdir = args.workdir.resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    archive = workdir / "wazuh-install-files.tar"
    if not args.skip_install:
        installer = workdir / "wazuh-install.sh"
        print(f"Downloading {INSTALL_URL}")
        urllib.request.urlretrieve(INSTALL_URL, installer)
        run("bash", str(installer), "-a", cwd=workdir)
    if not archive.is_file():
        raise RuntimeError(f"Installer password archive not found: {archive}")
    found = passwords(archive)
    set_logall_json(Path("/var/ossec/etc/ossec.conf"))
    run("/var/ossec/bin/wazuh-analysisd", "-t")
    run("systemctl", "restart", "wazuh-manager")
    set_filebeat_archives(Path("/etc/filebeat/filebeat.yml"))
    run("filebeat", "test", "config", "-c", "/etc/filebeat/filebeat.yml")
    run("systemctl", "restart", "filebeat")
    write_passwords(desktop_for_invoking_user(args.desktop) / "wazuh-server-passwords.txt", found)
    print("Server setup complete.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
