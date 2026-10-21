#!/usr/bin/env python3
"""Install the project's two systemd services using existing Linux dependencies."""

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


SERVICE_NAMES = ("wazuh-memory.service", "wazuh-frontend.service")
TEMPLATE_DIR = Path(__file__).resolve().parent


def systemd_quote(value, executable=False):
    """Quote one systemd value, including literal specifiers and ExecStart dollars."""
    value = str(value)
    if any(char in value for char in "\r\n\x00"):
        raise ValueError("Paths must not contain newlines or NUL characters")
    value = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    if executable:
        value = value.replace("$", "$$")
    return '"' + value + '"'


def render_units(project_dir, python, node, uid, gid):
    project_dir = Path(project_dir)
    replacements = {
        "PROJECT_DIR": systemd_quote(project_dir),
        "FRONTEND_DIR": systemd_quote(project_dir / "frontend"),
        "PYTHONPATH": systemd_quote("PYTHONPATH=" + str(project_dir / "src")),
        "PYTHON_EXEC": systemd_quote(python, executable=True),
        "NODE_EXEC": systemd_quote(node, executable=True),
        "USER": str(int(uid)),
        "GROUP": str(int(gid)),
    }
    units = {}
    for name in SERVICE_NAMES:
        content = (TEMPLATE_DIR / (name + ".in")).read_text(encoding="utf-8")
        for key, value in replacements.items():
            content = content.replace("@" + key + "@", value)
        if re.search(r"@[A-Z_]+@", content):
            raise ValueError("Unresolved placeholder in " + name)
        units[name] = content
    return units


def atomic_write(path, content):
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        os.chmod(temporary, 0o644)
        os.replace(temporary, str(path))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user", help="Linux account used to run both services (defaults to sudo caller)")
    parser.add_argument("--project-dir", type=Path, default=TEMPLATE_DIR.parent.parent)
    parser.add_argument("--python", type=Path, help="Existing venv Python; defaults to .venv/bin/python")
    parser.add_argument("--node", help="Absolute path to the existing Node.js executable")
    parser.add_argument("--dry-run", action="store_true", help="Validate files and print units without installing")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Run this installer inside the Linux VM, not on the Windows host")

    import pwd

    account = pwd.getpwnam(args.user or os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name)
    project = args.project_dir.expanduser().resolve()
    # Do not resolve the Python symlink: the venv path determines its site-packages.
    python = (args.python.expanduser() if args.python else project / ".venv/bin/python").absolute()
    node_path = args.node or shutil.which("node")
    if not node_path:
        parser.error("Node.js was not found; pass --node with its absolute executable path")
    node = Path(node_path).expanduser().absolute()
    required = [
        python, node, project / "src/service/memory.py", project / ".env",
        project / "frontend/.env.development", project / "frontend/node_modules/vite/bin/vite.js",
    ]
    for path in required:
        if not path.is_file():
            parser.error("Required file is missing: " + str(path))
    for path in (python, node):
        if not os.access(str(path), os.X_OK):
            parser.error("Executable permission is missing: " + str(path))
    units = render_units(project, python, node, account.pw_uid, account.pw_gid)
    print("Project: " + str(project))
    print("Service account: " + account.pw_name)
    if args.dry_run:
        for name, content in units.items():
            print("\n# /etc/systemd/system/" + name + "\n" + content)
        return 0
    if os.geteuid() != 0:
        parser.error("Installation requires root; use sudo, or use --dry-run to preview")
    if not shutil.which("systemctl"):
        parser.error("systemctl was not found; this installer requires systemd")
    destination = Path("/etc/systemd/system")
    for name, content in units.items():
        atomic_write(destination / name, content)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now"] + list(SERVICE_NAMES), check=True)
    print("Services installed and enabled. Check startup with:")
    print("  systemctl status " + " ".join(SERVICE_NAMES) + " --no-pager")
    print("  journalctl -u wazuh-memory -u wazuh-frontend -f")
    print("If updating already running services, restart them to load the new configuration.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print("Installation failed: " + str(exc), file=sys.stderr)
        sys.exit(1)
