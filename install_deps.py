#!/usr/bin/env python
"""One-shot installer for every dependency this project needs on a fresh virtualenv.

What it installs
    1. Runtime and dev dependencies declared in pyproject.toml (installed with
       `uv sync`, or with `uv pip` / `pip` from the parsed dependency lists when
       --mirror is used).
    2. Packages that src/ imports but pyproject.toml does not declare: nltk,
       networkx, pyvis, pdfminer.six, tiktoken, openai.
    3. NLP assets used by the knowledge-graph feature: spaCy + en_core_web_sm and
       the NLTK punkt / punkt_tab corpora (see README section 3.2).
    4. Config files copied from the examples when missing (.env,
       frontend/.env.development), Node.js 22 and pnpm setup on Linux when
       needed, and the frontend pnpm dependencies.

Usage (run from the project root, with any Python >= 3.11)
    python install_deps.py                  # install everything into <project>/.venv
    python install_deps.py --check          # print the plan, change nothing
    python install_deps.py --skip-frontend  # backend only
    python install_deps.py --no-dev         # skip the pyproject dev group
    python install_deps.py --no-optional    # skip spaCy / NLTK assets
    python install_deps.py --mirror https://pypi.tuna.tsinghua.edu.cn/simple

Verifying a clean install (targets a throwaway venv, ignores the caches):
    python install_deps.py --venv .venv-test --no-cache --skip-frontend
    # then: .venv-test/Scripts/python.exe -c "import spacy, nltk; ..."  and delete .venv-test

All messages are printed in English on purpose: non-ASCII console output is a
known source of mojibake in Windows PowerShell (README section 4.2).
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
VENV_DIR = PROJECT_ROOT / ".venv"
IS_WINDOWS = os.name == "nt"

# Packages imported by src/knowledge_graph but missing from pyproject.toml.
EXTRA_PACKAGES = [
    "nltk",
    "networkx",
    "pyvis",
    "pdfminer.six",
    "tiktoken",
    "openai",
]

# Optional knowledge-graph assets (README 3.2).
SPACY_PACKAGE = "spacy"
SPACY_MODEL = "en_core_web_sm"
SPACY_MODEL_FALLBACK_VERSION = "3.8.0"
# README 3.2 only mentions punkt, but the knowledge-graph code also tokenizes,
# POS-tags and lemmatizes (src/knowledge_graph/visualization.py, template.py),
# which needs the other three. Each one is caught as LookupError and silently
# degraded when absent, so they are easy to miss.
NLTK_CORPORA = ("punkt", "punkt_tab", "averaged_perceptron_tagger_eng", "wordnet")
# Where each optional asset is fetched from; used for the reachability probe.
SPACY_MODEL_HOST = "github.com"
NLTK_DATA_HOST = "raw.githubusercontent.com"

# Bounds for child processes: an unreachable host can otherwise hang a step
# forever, and large wheels can be slow on a throttled link.
DEFAULT_TIMEOUT = 900.0
DOWNLOAD_TIMEOUT = 3600.0
NLTK_TIMEOUT = 300.0

# Used only when pyproject.toml cannot be parsed (Python < 3.11).
FALLBACK_DEPENDENCIES = [
    "fastapi>=0.116.1",
    "langchain>=1.2.6",
    "langchain-core>=1.2.7",
    "langchain-huggingface>=1.2.0",
    "langchain-openai>=1.1.7",
    "langchain-pinecone>=0.0.1",
    "langgraph>=1.0.6",
    "pinecone>=8.0.0",
    "pydantic-settings>=2.12.0",
    "python-multipart>=0.0.20",
    "python-dotenv>=1.2.1",
    "requests>=2.32.5",
    "uvicorn>=0.40.0",
]
FALLBACK_DEV_DEPENDENCIES = [
    "black>=26.1.0",
    "langgraph-cli[inmem]>=0.4.11",
    "pytest>=9.0.2",
    "pytest-cov>=7.0.0",
    "requests-mock>=1.12.1",
    "ruff>=0.14.13",
]

FAILED: list[str] = []
# Optional assets (knowledge-graph NLP data) that could not be fetched; they do
# not fail the run because src/ falls back gracefully when they are missing.
OPTIONAL_FAILED: list[str] = []


def log(message: str) -> None:
    print(f"[install] {message}", flush=True)


def log_step(index: int, total: int, title: str) -> None:
    print(f"\n[{index}/{total}] {title}", flush=True)


def log_warn(message: str) -> None:
    print(f"[install][WARN] {message}", flush=True)


def log_error(message: str) -> None:
    print(f"[install][ERROR] {message}", flush=True)


def log_ok(message: str) -> None:
    print(f"[install][OK] {message}", flush=True)


def build_env(mirror: str | None = None, no_cache: bool = False) -> dict[str, str]:
    """Environment for every child process.

    Forces UTF-8 (non-ASCII console output is a known source of mojibake in
    Windows PowerShell, README 4.2), points uv's project sync at the venv we are
    actually installing into, and applies --mirror / --no-cache when given.
    """
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    # Without this, `uv sync` would ignore --venv and use <project>/.venv.
    env["UV_PROJECT_ENVIRONMENT"] = str(VENV_DIR)
    if mirror:
        env["UV_DEFAULT_INDEX"] = mirror
        env["PIP_INDEX_URL"] = mirror
    if no_cache:
        env["UV_NO_CACHE"] = "1"
        env["PIP_NO_CACHE_DIR"] = "1"
    return env


def run(
    command: list[str],
    args: argparse.Namespace,
    cwd: Path = PROJECT_ROOT,
    check_only_ok: bool = True,
    timeout: float | None = DEFAULT_TIMEOUT,
) -> bool:
    """Run a command; print it instead of running it when --check is set.

    Every command is bounded by `timeout` seconds: an unreachable download host
    can otherwise stall a step indefinitely (NLTK retries without a limit).
    """
    printable = " ".join(str(part) for part in command)
    log(f"$ {printable}")
    if args.check:
        return check_only_ok
    try:
        result = subprocess.run(
            [str(part) for part in command],
            cwd=str(cwd),
            env=build_env(args.mirror, args.no_cache),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        log_error(f"command timed out after {timeout:g}s: {printable}")
        return False
    except OSError as exc:
        log_error(f"could not start command: {exc}")
        return False
    if result.returncode != 0:
        log_error(f"command failed with exit code {result.returncode}")
        return False
    return True


def capture(command: list[str], timeout: float = 120.0) -> str | None:
    """Run a command and return its stripped stdout, or None if it failed."""
    try:
        result = subprocess.run(
            [str(part) for part in command],
            capture_output=True,
            text=True,
            env=build_env(),
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def install_spacy_model_direct(args: argparse.Namespace, interpreter: Path, uv: str | None) -> bool:
    """Install the model wheel straight from GitHub releases.

    Used when `spacy download` cannot run because its compatibility table on
    raw.githubusercontent.com is unreachable. The model version must match the
    installed spaCy version, so it is derived from `spacy.__version__`.
    """
    version = capture([str(interpreter), "-c", "import spacy; print(spacy.__version__)"])
    parts = (version or SPACY_MODEL_FALLBACK_VERSION).split(".")
    spec = ".".join(parts[:2] + ["0"]) if len(parts) >= 2 else SPACY_MODEL_FALLBACK_VERSION
    url = (
        f"https://github.com/explosion/spacy-models/releases/download/"
        f"{SPACY_MODEL}-{spec}/{SPACY_MODEL}-{spec}-py3-none-any.whl"
    )
    log_warn(f"trying the model wheel directly: {url}")
    if uv:
        command = [uv, "pip", "install", "--python", str(interpreter), url]
    else:
        command = [str(interpreter), "-m", "pip", "install", url]
    return run(command, args, timeout=DOWNLOAD_TIMEOUT)


def host_reachable(host: str, port: int = 443, timeout: float = 6.0) -> bool:
    """Cheap pre-flight probe, used to skip download hosts that are unreachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def python_version_of(executable: Path) -> tuple[int, int] | None:
    try:
        out = subprocess.run(
            [str(executable), "-c", "import sys; print(f'{sys.version_info[0]} {sys.version_info[1]}')"],
            capture_output=True,
            text=True,
            env=build_env(),
        )
    except OSError:
        return None
    if out.returncode != 0:
        return None
    try:
        major, minor = out.stdout.split()
        return int(major), int(minor)
    except ValueError:
        return None


def venv_python() -> Path:
    return VENV_DIR / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")


def find_pnpm() -> str | None:
    for name in ("pnpm", "pnpm.cmd", "pnpm.exe"):
        found = shutil.which(name)
        if found:
            return found
    return None


def node_is_compatible() -> bool:
    """The frontend requires Node.js 20.11 or newer."""
    version = capture(["node", "--version"])
    if not version:
        return False
    try:
        major, minor, *_ = (int(part) for part in version.lstrip("v").split("."))
    except ValueError:
        return False
    return (major, minor) >= (20, 11)


def ensure_pnpm(args: argparse.Namespace) -> str | None:
    """Prepare a user-owned Node.js and pnpm on Linux when they are missing.

    Use nvm in the user's home rather than changing the distribution's Node.js.
    The current Python process gets the nvm Node directory added to PATH, so
    pnpm is usable immediately without asking the user to reopen the shell.
    """
    pnpm = find_pnpm()
    if pnpm and node_is_compatible():
        return pnpm
    if args.check:
        log("would install Node.js 22 and enable pnpm if needed")
        return None
    if IS_WINDOWS:
        log_error("automatic Node.js setup is supported on Linux; install Node.js 20.11+ and pnpm")
        return None

    nvm_dir = Path.home() / ".nvm"
    nvm_script = nvm_dir / "nvm.sh"
    if not nvm_script.is_file():
        if nvm_dir.exists():
            log_error(f"{nvm_dir} exists but nvm.sh is missing; inspect it before retrying")
            return None
        git = shutil.which("git")
        if not git:
            log_error("git is required to install nvm; install it with 'sudo apt install git'")
            return None
        log("installing nvm v0.40.8 in the current user's home directory")
        if not run([git, "clone", "--depth", "1", "--branch", "v0.40.8",
                    "https://github.com/nvm-sh/nvm.git", str(nvm_dir)], args,
                   timeout=DOWNLOAD_TIMEOUT):
            return None

    # nvm is a shell function, so source it in bash and ask it for Node's bin
    # directory. Do not source anything from the project repository.
    bash = shutil.which("bash")
    if not bash:
        log_error("bash is required for nvm")
        return None
    script = 'source "$1" && nvm install 22 >/dev/null && nvm which 22'
    log("installing or selecting Node.js 22 with nvm")
    try:
        result = subprocess.run(
            [bash, "-c", script, "bash", str(nvm_script)],
            capture_output=True, text=True, timeout=DOWNLOAD_TIMEOUT,
            env=build_env(args.mirror, args.no_cache),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log_error(f"Node.js setup failed: {exc}")
        return None
    if result.returncode:
        log_error(f"Node.js setup failed: {result.stderr.strip()}")
        return None
    node_path = Path(result.stdout.strip().splitlines()[-1])
    if not node_path.is_file():
        log_error("nvm did not return a usable Node.js executable")
        return None
    os.environ["PATH"] = str(node_path.parent) + os.pathsep + os.environ.get("PATH", "")
    if not node_is_compatible():
        log_error("Node.js 20.11+ is still unavailable after installation")
        return None
    corepack = shutil.which("corepack")
    if not corepack:
        log_error("corepack was not included with Node.js; install it and rerun")
        return None
    if not run([corepack, "enable"], args):
        return None
    pnpm = find_pnpm()
    if not pnpm:
        log_error("pnpm is unavailable after enabling Corepack")
    return pnpm


def read_declared_dependencies(with_dev: bool) -> list[str]:
    """Read dependencies from pyproject.toml so the lists never drift."""
    try:
        import tomllib
    except ModuleNotFoundError:
        log_warn("tomllib unavailable (Python < 3.11); using the built-in dependency list")
        return FALLBACK_DEPENDENCIES + (FALLBACK_DEV_DEPENDENCIES if with_dev else [])
    with open(PROJECT_ROOT / "pyproject.toml", "rb") as handle:
        data = tomllib.load(handle)
    dependencies = list(data.get("project", {}).get("dependencies", []))
    if with_dev:
        groups = data.get("dependency-groups", {})
        dependencies += list(groups.get("dev", []))
    if not dependencies:
        return FALLBACK_DEPENDENCIES + (FALLBACK_DEV_DEPENDENCIES if with_dev else [])
    return dependencies


def ensure_venv(args: argparse.Namespace, uv: str | None) -> bool:
    if venv_python().exists():
        version = python_version_of(venv_python())
        shown = f"{version[0]}.{version[1]}" if version else "unknown"
        log_ok(f"virtual environment found: {VENV_DIR} (Python {shown})")
        if version and version < (3, 11):
            log_error("the project requires Python 3.11 or newer; recreate .venv with a newer Python")
            return False
        return True

    log(f"no virtual environment at {VENV_DIR}; creating one")
    if uv:
        return run([uv, "venv", str(VENV_DIR), "--python", "3.11"], args) or run(
            [uv, "venv", str(VENV_DIR)], args
        )
    return run([sys.executable, "-m", "venv", str(VENV_DIR)], args)


def install_declared_dependencies(args: argparse.Namespace, uv: str | None) -> bool:
    """Install pyproject.toml dependencies (and the project itself, editable)."""
    if uv and not args.mirror:
        command = [uv, "sync"]
        if not args.with_dev:
            command.append("--no-dev")
        if run(command, args):
            log_ok("pyproject.toml dependencies installed with uv sync")
            return True
        log_warn("uv sync failed; falling back to an explicit package install")

    dependencies = read_declared_dependencies(args.with_dev)
    if uv:
        command = [uv, "pip", "install", "--python", str(venv_python())]
    else:
        command = [str(venv_python()), "-m", "pip", "install"]
    # -e . installs the project itself, which uv sync does automatically.
    command += ["-e", str(PROJECT_ROOT)] + dependencies
    if run(command, args, cwd=PROJECT_ROOT):
        log_ok("pyproject.toml dependencies installed")
        return True
    return False


def install_extra_packages(args: argparse.Namespace, uv: str | None) -> bool:
    if uv:
        command = [uv, "pip", "install", "--python", str(venv_python())] + EXTRA_PACKAGES
    else:
        command = [str(venv_python()), "-m", "pip", "install"] + EXTRA_PACKAGES
    if run(command, args):
        log_ok("extra packages installed: " + ", ".join(EXTRA_PACKAGES))
        return True
    return False


def install_nlp_assets(args: argparse.Namespace, uv: str | None) -> None:
    """spaCy + en_core_web_sm and the NLTK corpora; failures are not fatal.

    The spaCy model comes from GitHub release assets, the NLTK corpora come from
    raw.githubusercontent.com. The project code catches LookupError and falls
    back to plain splitting when the corpora are absent, so a failure here only
    degrades the knowledge-graph output quality.
    """
    interpreter = venv_python()
    if uv:
        spacy_command = [uv, "pip", "install", "--python", str(interpreter), SPACY_PACKAGE]
    else:
        spacy_command = [str(interpreter), "-m", "pip", "install", SPACY_PACKAGE]
    if not run(spacy_command, args):
        OPTIONAL_FAILED.append(f"install {SPACY_PACKAGE}")

    if not host_reachable(SPACY_MODEL_HOST):
        OPTIONAL_FAILED.append(f"download spaCy model {SPACY_MODEL} ({SPACY_MODEL_HOST} unreachable)")
        log_warn(f"{SPACY_MODEL_HOST} is unreachable, skipping the spaCy model download.")
    elif not run(
        [str(interpreter), "-m", "spacy", "download", SPACY_MODEL],
        args,
        timeout=DOWNLOAD_TIMEOUT,
    ):
        log_warn(f"'spacy download' failed: it reads its compatibility table from {NLTK_DATA_HOST},")
        log_warn("which is frequently unreachable on this network. Trying GitHub releases instead.")
        if not install_spacy_model_direct(args, interpreter, uv):
            OPTIONAL_FAILED.append(f"download spaCy model {SPACY_MODEL}")

    if not host_reachable(NLTK_DATA_HOST):
        OPTIONAL_FAILED.append(
            "download NLTK corpora " + ", ".join(NLTK_CORPORA) + f" ({NLTK_DATA_HOST} unreachable)"
        )
        log_warn(f"{NLTK_DATA_HOST} is unreachable from this machine, so the NLTK corpora")
        log_warn("cannot be fetched without a VPN. The code catches LookupError and falls back")
        log_warn("to simple tokenization, so this only lowers knowledge-graph output quality.")
        log_warn("To add them later, copy the tokenizers/punkt and tokenizers/punkt_tab folders")
        log_warn('into the NLTK search path (python -c "import nltk; print(nltk.data.path)").')
        return

    # nltk.download sets no socket timeout of its own, so a blackholed host
    # stalls it indefinitely; bound it here as well as at the process level.
    nltk_snippet = (
        "import socket, sys, nltk; "
        "socket.setdefaulttimeout(30); "
        f"results = [nltk.download(name, quiet=True) for name in {NLTK_CORPORA!r}]; "
        "sys.exit(0 if all(results) else 1)"
    )
    if not run([str(interpreter), "-c", nltk_snippet], args, timeout=NLTK_TIMEOUT):
        OPTIONAL_FAILED.append("download NLTK corpora " + ", ".join(NLTK_CORPORA))
        log_warn("The code falls back to simple tokenization when the corpora are missing.")


def copy_file_if_missing(source: Path, target: Path, args: argparse.Namespace) -> None:
    if target.exists():
        log_ok(f"{target.relative_to(PROJECT_ROOT)} already exists, left untouched")
        return
    if not source.exists():
        log_warn(f"{source} not found, skipped")
        return
    if args.check:
        log(f"$ copy {source} -> {target}")
        return
    shutil.copyfile(source, target)
    log_ok(f"created {target.relative_to(PROJECT_ROOT)} from {source.name} (fill in the real values)")


def install_frontend(args: argparse.Namespace, pnpm: str | None) -> bool:
    if not FRONTEND_DIR.is_dir():
        log_warn("frontend directory not found, skipped")
        return True
    if args.check and not pnpm:
        log("would run pnpm install after Node.js and pnpm setup")
        return True
    if not pnpm:
        log_error("pnpm is unavailable; automatic Node.js/Corepack setup did not complete")
        return False
    if run([pnpm, "install"], args, cwd=FRONTEND_DIR):
        return True

    # pnpm 10+ exits non-zero after a successful install when it skipped
    # dependency build scripts (ERR_PNPM_IGNORED_BUILDS). The packages are
    # installed at that point, so treat it as a warning, not a failure.
    if (FRONTEND_DIR / "node_modules").is_dir():
        log_warn("pnpm exited non-zero, but node_modules exists - the install itself succeeded.")
        log_warn("If it reported ignored build scripts, run 'pnpm approve-builds' in frontend/")
        log_warn("and pick the packages it lists (README 4.1), then rerun 'pnpm install'.")
        return True
    return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install every dependency required by wazuh_ai_agent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--check", action="store_true", help="print the plan without installing")
    parser.add_argument("--no-dev", dest="with_dev", action="store_false", help="skip the dev group")
    parser.add_argument(
        "--no-optional",
        dest="with_optional",
        action="store_false",
        help="skip spaCy, en_core_web_sm and the NLTK corpora",
    )
    parser.add_argument("--skip-frontend", action="store_true", help="do not run pnpm install")
    parser.add_argument("--mirror", metavar="URL", default=None, help="PyPI mirror, e.g. a Tsinghua URL")
    parser.add_argument(
        "--venv",
        metavar="PATH",
        default=None,
        help="install into this virtualenv instead of <project>/.venv (created if missing)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="ignore the uv and pip caches, forcing every package to be downloaded again",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.venv:
        global VENV_DIR
        VENV_DIR = Path(args.venv).expanduser()
        if not VENV_DIR.is_absolute():
            VENV_DIR = (PROJECT_ROOT / VENV_DIR).resolve()

    steps = [
        "check the environment and the virtualenv",
        "install dependencies declared in pyproject.toml",
        "install packages missing from pyproject.toml",
        "install optional NLP assets (spaCy model, NLTK corpora)",
        "create config files from the examples",
        "install frontend dependencies",
    ]
    if not args.with_optional:
        steps[3] = "optional NLP assets skipped"
    if args.skip_frontend:
        steps[5] = "frontend dependencies skipped"

    log(f"project root: {PROJECT_ROOT}")
    log(f"target virtualenv: {VENV_DIR}" + ("  (from --venv)" if args.venv else ""))
    if args.no_cache:
        log("--no-cache: every package will be downloaded again")
    if args.check:
        log("running in check mode, nothing will be installed")

    uv = shutil.which("uv")
    pnpm = find_pnpm()
    log(f"uv: {uv or 'NOT FOUND'}")
    log(f"pnpm: {pnpm or 'NOT FOUND (will set up automatically on Linux)'}")
    if not uv:
        log_warn("uv not found; falling back to pip (README 2.2.1: winget install --id astral-sh.uv -e)")
    if python_version_of(Path(sys.executable)) is None:
        log_warn("could not determine the version of the running interpreter")

    total = len(steps)
    if not ensure_venv(args, uv):
        FAILED.append("prepare the virtual environment")
        return finish()

    log_step(2, total, steps[1])
    if not install_declared_dependencies(args, uv):
        FAILED.append("install pyproject.toml dependencies")

    log_step(3, total, steps[2])
    if not install_extra_packages(args, uv):
        FAILED.append("install extra packages")

    if args.with_optional:
        log_step(4, total, steps[3])
        install_nlp_assets(args, uv)
    else:
        log_step(4, total, steps[3])

    log_step(5, total, steps[4])
    copy_file_if_missing(PROJECT_ROOT / ".env.example", PROJECT_ROOT / ".env", args)
    # Vite gives .env.development priority over .env, so dropping the example
    # copy next to a .env the user configured would silently override it.
    if (FRONTEND_DIR / ".env.development").exists() or (FRONTEND_DIR / ".env").exists():
        log_ok("frontend env already configured, left untouched")
    else:
        copy_file_if_missing(FRONTEND_DIR / ".env.example", FRONTEND_DIR / ".env.development", args)

    log_step(6, total, steps[5])
    if not args.skip_frontend:
        pnpm = ensure_pnpm(args)
        if not install_frontend(args, pnpm):
            FAILED.append("install frontend dependencies")

    return finish()


def finish() -> int:
    print("", flush=True)
    if OPTIONAL_FAILED:
        log_warn("optional assets not installed (the project still runs without them):")
        for item in OPTIONAL_FAILED:
            print(f"  - {item}", flush=True)
        print("", flush=True)
    if FAILED:
        log_error("finished with failures:")
        for item in FAILED:
            print(f"  - {item}", flush=True)
        print("", flush=True)
        log("rerun this script after fixing the cause; see README chapter 4.")
        return 1
    log_ok("all required dependencies are installed")
    log("next steps: fill in .env and frontend/.env.development (README 3.1), then start the services:")
    log("  uv run python -m src.service.memory")
    log("  uv run wazuh-topology-api")
    log("  cd frontend && pnpm dev")
    log("note: 'uv sync' uninstalls the packages added in step 3 and step 4, because")
    log("      pyproject.toml does not declare them. 'uv run <cmd>' does not. If you ever")
    log("      run 'uv sync' by hand, rerun this script to put them back.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("", flush=True)
        log_error("interrupted by the user")
        sys.exit(130)
