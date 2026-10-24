#!/usr/bin/env python3
"""Run a script only when its sha256 is allowlisted and the git tree is clean.

The work tree is checked first. A repo filter driver or hook refuses before
status. Git calls do not start hooks and do not refresh the index.
Only then are the script bytes read, and only when they match HEAD. Those
bytes are what runs. The path is not executed.
The receipt is passed through the safe-helpers export scrubber.
This script does not open the network.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


class RunnerError(Exception):
    """The request cannot be checked. Exit 2."""


class ScriptRejected(Exception):
    """Policy refusal before the script starts. Exit 1."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def load_scrubber():
    path = Path(__file__).resolve().parents[1] / "safe-helpers" / "export_scrub.py"
    if not path.is_file():
        raise RunnerError("scrubber is missing")
    spec = importlib.util.spec_from_file_location("export_scrub", path)
    if spec is None or spec.loader is None:
        raise RunnerError("scrubber is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def file_sha256(path: Path) -> str:
    return hashlib.sha256(read_regular_file(path)).hexdigest()


def read_regular_file(path: Path) -> bytes:
    """Read a regular file without following a final symlink."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ScriptRejected("symlink") from exc
        if exc.errno == errno.ENOENT:
            raise RunnerError("script is missing") from exc
        raise RunnerError("script could not be read") from exc
    try:
        return _read_regular_fd(fd)
    finally:
        os.close(fd)


def _read_regular_fd(fd: int) -> bytes:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise ScriptRejected("not-a-file")
    chunks: list[bytes] = []
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        chunks.append(block)
    return b"".join(chunks)


def lexical_relative(root: Path, script: Path) -> Path | None:
    """Path of script under root, without resolving symlinks inside root."""
    root_abs = Path(os.path.abspath(root))
    root_real = Path(os.path.realpath(root))
    script_abs = Path(os.path.abspath(script))
    for base in (root_abs, root_real):
        try:
            rel = script_abs.relative_to(base)
        except ValueError:
            continue
        if not rel.parts or any(part in ("", ".", "..") for part in rel.parts):
            return None
        return rel
    return None


def _is_symlink_at(dir_fd: int, name: str) -> bool:
    try:
        info = os.lstat(name, dir_fd=dir_fd)
    except OSError:
        return False
    return stat.S_ISLNK(info.st_mode)


def read_under_root(root: Path, script: Path) -> bytes:
    """Read script bytes by walking from root. A symlink component is refused."""
    root_real = Path(os.path.realpath(root))
    if not root_real.is_dir():
        raise RunnerError("root is missing")
    rel = lexical_relative(root, script)
    if rel is None:
        raise ScriptRejected("outside-root")
    try:
        dir_fd = os.open(
            root_real,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ScriptRejected("symlink") from exc
        raise RunnerError("root is missing") from exc
    fd = dir_fd
    try:
        for index, part in enumerate(rel.parts):
            last = index == len(rel.parts) - 1
            if _is_symlink_at(fd, part):
                raise ScriptRejected("symlink")
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            if not last:
                flags |= os.O_DIRECTORY
            try:
                opened = os.open(part, flags, dir_fd=fd)
            except OSError as exc:
                # A directory symlink with O_DIRECTORY returns ENOTDIR, not ELOOP.
                if exc.errno == errno.ELOOP or (
                    exc.errno == errno.ENOTDIR and _is_symlink_at(fd, part)
                ):
                    raise ScriptRejected("symlink") from exc
                if exc.errno == errno.ENOENT:
                    raise RunnerError("script is missing") from exc
                if exc.errno == errno.ENOTDIR:
                    raise ScriptRejected("not-a-file") from exc
                raise RunnerError("script could not be read") from exc
            if fd != dir_fd:
                os.close(fd)
            fd = opened
        return _read_regular_fd(fd)
    finally:
        if fd != dir_fd:
            os.close(fd)
        os.close(dir_fd)


def parse_allowlist(text: str) -> list[str]:
    hashes: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        token = stripped.split()[0].lower()
        if len(token) != 64 or any(char not in "0123456789abcdef" for char in token):
            raise RunnerError("allowlist line is not a sha256")
        hashes.append(token)
    return hashes


def git_env(root: Path) -> dict[str, str]:
    """Local git only. Repo aliases and the caller's git env are not used."""
    root_real = Path(os.path.realpath(root))
    env = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CEILING_DIRECTORIES": str(root_real.parent),
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    return env


_EMPTY_HOOKS: str | None = None


def _empty_hooks_dir() -> str:
    """Empty directory used as core.hooksPath so repo hooks are not started."""
    global _EMPTY_HOOKS
    current = _EMPTY_HOOKS
    if current is not None and os.path.isdir(current) and not os.listdir(current):
        return current
    path = tempfile.mkdtemp(prefix="allowlist-hooks-")
    os.chmod(path, 0o700)
    _EMPTY_HOOKS = path
    return path


def _git_prefix(root: Path, *, hooks: bool = True, fsmonitor: bool = True) -> list[str]:
    """Hardened git invocation. Does not consult filter drivers or repo hooks."""
    prefix = [
        "git",
        "--no-optional-locks",
    ]
    if hooks:
        # Omit this when asking git whether the repo itself sets core.hooksPath.
        prefix.extend(["-c", "core.hooksPath=" + _empty_hooks_dir()])
    if fsmonitor:
        # Omit this when asking git whether the repo itself sets core.fsmonitor.
        prefix.extend(["-c", "core.fsmonitor=false"])
    prefix.extend([
        "-c",
        "core.untrackedCache=false",
        "-c",
        "alias.status=",
        "-c",
        "alias.rev-parse=",
        "-c",
        "alias.ls-files=",
        "-c",
        "alias.cat-file=",
        "-c",
        "alias.config=",
        "-C",
        str(Path(os.path.realpath(root))),
    ])
    return prefix


def _filter_driver_name(key: str) -> str | None:
    if not key.startswith("filter."):
        return None
    rest = key[len("filter.") :]
    for suffix in (".clean", ".smudge", ".process", ".required"):
        if rest.endswith(suffix):
            name = rest[: -len(suffix)]
            if name and not name.startswith("-") and all(
                char.isalnum() or char in "._-" for char in name
            ):
                return name
            return None
    return None


def local_filter_drivers(root: Path) -> tuple[str, ...] | None:
    """Repo filter drivers, including ones included from repo config.

    None means the config could not be read. Exit 1 is an empty list.
    This read does not run clean, smudge, or process commands.
    """
    names: set[str] = set()
    failed = False
    root_real = Path(os.path.realpath(root))
    for extra in (
        ("--local", "--get-regexp", r"^filter\."),
        ("--get-regexp", r"^filter\."),
    ):
        try:
            probe = subprocess.run(
                [*_git_prefix(root), "config", *extra],
                capture_output=True,
                encoding="utf-8",
                errors="surrogateescape",
                env=git_env(root),
                cwd=str(root_real),
                check=False,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise RunnerError("git is missing") from exc
        if probe.returncode == 1:
            continue
        if probe.returncode != 0:
            failed = True
            continue
        for line in probe.stdout.splitlines():
            if not line.strip():
                continue
            name = _filter_driver_name(line.split()[0])
            if name:
                names.add(name)
    if failed and not names:
        return None
    return tuple(sorted(names))


def _filter_override_args(drivers: tuple[str, ...] | None) -> list[str]:
    flags: list[str] = []
    for name in drivers or ():
        for key in ("clean", "smudge", "process"):
            flags.extend(["-c", f"filter.{name}.{key}="])
        flags.extend(["-c", f"filter.{name}.required=false"])
    return flags


def git_argv(root: Path, *args: str) -> list[str]:
    prefix = _git_prefix(root)
    overrides = _filter_override_args(local_filter_drivers(root))
    # -C is the last prefix pair. Overrides stay in front of the subcommand.
    return [*prefix[:-2], *overrides, *prefix[-2:], *args]


def git_probe(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    try:
        root_real = Path(os.path.realpath(root))
        return subprocess.run(
            git_argv(root, *args),
            capture_output=True,
            encoding="utf-8",
            errors="surrogateescape",
            env=git_env(root),
            cwd=str(root_real),
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise RunnerError("git is missing") from exc


def index_flags_are_dirty(text: str) -> bool:
    """Skip-worktree (S) and assume-unchanged (lowercase, including h) are dirty."""
    for line in text.splitlines():
        if not line:
            continue
        tag = line[0]
        if tag == "S" or tag.islower():
            return True
    return False


def _line_selects_filter(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    for token in stripped.split()[1:]:
        if token.startswith(("!", "-")) or not token.startswith("filter="):
            continue
        if token.split("=", 1)[1]:
            return True
    return False


def _attributes_file_selects_filter(path: Path) -> bool:
    """True when this attributes file selects a filter, or cannot be read safely."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if stat.S_ISLNK(info.st_mode):
        return True
    if not stat.S_ISREG(info.st_mode):
        return False
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return True
    try:
        data = os.read(fd, 1024 * 1024 + 1)
    finally:
        os.close(fd)
    if len(data) > 1024 * 1024:
        return True
    text = data.decode("utf-8", errors="replace")
    return any(_line_selects_filter(line) for line in text.splitlines())


def _info_attributes_path(root_real: Path) -> Path | None:
    git_meta = root_real / ".git"
    try:
        info = git_meta.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(info.st_mode):
        return git_meta
    if stat.S_ISDIR(info.st_mode):
        return git_meta / "info" / "attributes"
    if not stat.S_ISREG(info.st_mode):
        return None
    try:
        fd = os.open(git_meta, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return git_meta
    try:
        raw = os.read(fd, 4096)
    finally:
        os.close(fd)
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if line.startswith("gitdir: "):
            git_dir = Path(line[len("gitdir: ") :].strip())
            if not git_dir.is_absolute():
                git_dir = root_real / git_dir
            return git_dir / "info" / "attributes"
    return None


def _config_key_is_set(root: Path, key: str) -> bool | None:
    """True when repo config sets key. False when unset. None when unreadable."""
    failed = False
    root_real = Path(os.path.realpath(root))
    pattern = "^" + key.replace(".", r"\.") + "$"
    for extra in (
        ("--local", "--get-regexp", pattern),
        ("--get-regexp", pattern),
    ):
        try:
            probe = subprocess.run(
                [*_git_prefix(root, hooks=False), "config", *extra],
                capture_output=True,
                encoding="utf-8",
                errors="surrogateescape",
                env=git_env(root),
                cwd=str(root_real),
                check=False,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise RunnerError("git is missing") from exc
        if probe.returncode == 0 and probe.stdout.strip():
            return True
        if probe.returncode == 1:
            continue
        if probe.returncode != 0:
            failed = True
    if failed:
        return None
    return False


def _rev_parse_lines(root: Path, *args: str) -> list[str] | None:
    """Absolute rev-parse output. None when git cannot answer."""
    try:
        probe = subprocess.run(
            [*_git_prefix(root, hooks=False), "rev-parse", *args],
            capture_output=True,
            encoding="utf-8",
            errors="surrogateescape",
            env=git_env(root),
            cwd=str(Path(os.path.realpath(root))),
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise RunnerError("git is missing") from exc
    if probe.returncode != 0:
        return None
    lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
    return lines or None


def _git_layout(root: Path) -> tuple[Path, Path, Path] | None:
    """Per-worktree git dir, common git dir, and the hooks path git would use."""
    lines = _rev_parse_lines(
        root,
        "--path-format=absolute",
        "--absolute-git-dir",
        "--git-common-dir",
        "--git-path",
        "hooks",
    )
    if lines is None or len(lines) < 3:
        return None
    return Path(lines[0]), Path(lines[1]), Path(lines[2])


def _directory_has_executable_hook(hooks: Path) -> bool:
    """True when this hooks directory has an executable hook other than *.sample."""
    try:
        info = hooks.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if stat.S_ISLNK(info.st_mode):
        return True
    if not stat.S_ISDIR(info.st_mode):
        return False
    try:
        names = os.listdir(hooks)
    except OSError:
        return True
    for name in names:
        if name.endswith(".sample") or name.startswith("."):
            continue
        path = hooks / name
        try:
            entry = path.lstat()
        except OSError:
            return True
        if stat.S_ISLNK(entry.st_mode):
            return True
        if stat.S_ISREG(entry.st_mode) and entry.st_mode & 0o111:
            return True
    return False


def _config_text_is_unsafe(text: str, *, include_fsmonitor: bool) -> bool:
    """True when an ini config selects a filter, hooksPath, or (optionally) fsmonitor."""
    section = ""
    subsection = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            body = stripped[1:-1].strip()
            if " " in body:
                name, _, rest = body.partition(" ")
                section = name.strip().lower()
                subsection = rest.strip().strip('"').lower()
            else:
                section = body.lower()
                subsection = ""
            continue
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip().lower()
        if not value.strip():
            continue
        if section == "filter" and subsection and key in {"clean", "smudge", "process", "required"}:
            return True
        if section == "core" and key == "hookspath":
            return True
        if (
            include_fsmonitor
            and section == "core"
            and key == "fsmonitor"
            and value.strip().lower() not in {"false", "0"}
        ):
            return True
    return False


def _config_file_is_unsafe(path: Path, *, include_fsmonitor: bool) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return True
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return True
    try:
        data = os.read(fd, 1024 * 1024 + 1)
    finally:
        os.close(fd)
    if len(data) > 1024 * 1024:
        return True
    return _config_text_is_unsafe(
        data.decode("utf-8", errors="replace"),
        include_fsmonitor=include_fsmonitor,
    )


def _config_probe_is_unsafe(text: str, pattern: str) -> bool:
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2 or not parts[1].strip():
            continue
        if pattern.endswith("fsmonitor$") and parts[1].strip().lower() in {"false", "0"}:
            continue
        return True
    return False


def _worktree_git_config_is_unsafe(root: Path) -> bool:
    """True when extensions.worktreeConfig exposes a filter, hooksPath, or fsmonitor."""
    enabled = _config_key_is_set(root, "extensions.worktreeConfig")
    if enabled is None:
        return True
    if not enabled:
        return False
    root_real = Path(os.path.realpath(root))
    for pattern in (r"^filter\.", r"^core\.hooksPath$", r"^core\.fsmonitor$"):
        try:
            probe = subprocess.run(
                [
                    *_git_prefix(root, hooks=False, fsmonitor=False),
                    "config",
                    "--worktree",
                    "--get-regexp",
                    pattern,
                ],
                capture_output=True,
                encoding="utf-8",
                errors="surrogateescape",
                env=git_env(root),
                cwd=str(root_real),
                check=False,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise RunnerError("git is missing") from exc
        if probe.returncode == 0 and _config_probe_is_unsafe(probe.stdout, pattern):
            return True
        if probe.returncode in (0, 1, 128):
            continue
        return True
    return False


def repo_hooks_are_unsafe(root: Path) -> bool:
    """Refuse when either git dir has an executable hook or selects hook config."""
    layout = _git_layout(root)
    if layout is None:
        return True
    git_dir, common, hooks_path = layout
    seen: set[str] = set()
    for directory in (git_dir / "hooks", common / "hooks", hooks_path):
        identity = str(directory)
        if identity in seen:
            continue
        seen.add(identity)
        if _directory_has_executable_hook(directory):
            return True
    if _config_file_is_unsafe(common / "config", include_fsmonitor=False):
        return True
    if _config_file_is_unsafe(git_dir / "config.worktree", include_fsmonitor=True):
        return True
    if _worktree_git_config_is_unsafe(root):
        return True
    configured = _config_key_is_set(root, "core.hooksPath")
    return configured is None or configured


def attributes_select_filter(root: Path) -> bool:
    """True when attributes would select a clean, smudge, or process filter."""
    root_real = Path(os.path.realpath(root))
    info_attributes = _info_attributes_path(root_real)
    if info_attributes is not None and _attributes_file_selects_filter(info_attributes):
        return True
    layout = _git_layout(root)
    if layout is not None:
        git_dir, common, _hooks = layout
        for extra in (common / "info" / "attributes", git_dir / "info" / "attributes"):
            if _attributes_file_selects_filter(extra):
                return True
    for dirpath, dirnames, filenames in os.walk(root_real, followlinks=False):
        kept: list[str] = []
        for name in dirnames:
            path = os.path.join(dirpath, name)
            if name == ".git" or os.path.islink(path):
                continue
            kept.append(name)
        dirnames[:] = kept
        if ".gitattributes" in filenames and _attributes_file_selects_filter(
            Path(dirpath) / ".gitattributes"
        ):
            return True
    return False


def tree_state(root: Path) -> str:
    """Return clean, dirty, not-a-repo, or unsafe-config. Git stays on this machine."""
    root_real = Path(os.path.realpath(root))
    drivers = local_filter_drivers(root)
    probe = git_probe(root, "rev-parse", "--show-toplevel")
    if probe.returncode != 0:
        return "not-a-repo"
    top = probe.stdout.strip()
    if not top or os.path.realpath(top) != str(root_real):
        return "not-a-repo"
    if (
        drivers is None
        or drivers
        or attributes_select_filter(root)
        or repo_hooks_are_unsafe(root)
    ):
        return "unsafe-config"
    status = git_probe(root, "status", "--porcelain", "--ignored", "--untracked-files=all")
    if status.returncode != 0:
        return "not-a-repo"
    if status.stdout.strip():
        return "dirty"
    listed = git_probe(root, "ls-files", "-v")
    if listed.returncode != 0:
        return "not-a-repo"
    if index_flags_are_dirty(listed.stdout):
        return "dirty"
    return "clean"


def head_blob(root: Path, rel: Path) -> bytes | None:
    """Bytes of HEAD:rel, or None when that path is not a blob in HEAD."""
    spec = "HEAD:" + rel.as_posix()
    try:
        probe = subprocess.run(
            git_argv(root, "cat-file", "blob", spec),
            capture_output=True,
            env=git_env(root),
            cwd=str(Path(os.path.realpath(root))),
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise RunnerError("git is missing") from exc
    if probe.returncode != 0:
        return None
    return probe.stdout


def read_matching_head(root: Path, script: Path) -> bytes:
    """Two no-follow reads, equal to each other and to the HEAD blob."""
    rel = lexical_relative(root, script)
    if rel is None:
        raise ScriptRejected("outside-root")
    first = read_under_root(root, script)
    try:
        second = read_under_root(root, script)
    except RunnerError as exc:
        raise ScriptRejected("changed") from exc
    if first != second:
        raise ScriptRejected("changed")
    blob = head_blob(root, rel)
    if blob is None:
        raise ScriptRejected("not-in-head")
    if blob != first:
        raise ScriptRejected("changed")
    return first


def child_command() -> list[str]:
    return [sys.executable, "-I", "-B", "-"]


def child_env() -> dict[str, str]:
    """No caller PYTHON* variables, startup files, or loader overrides."""
    env: dict[str, str] = {}
    path = os.environ.get("PATH")
    if path:
        env["PATH"] = path
    for key in ("LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    return env


def decide(root: Path, script: Path, allowlist: list[str]) -> dict[str, object]:
    state = tree_state(root)
    if state != "clean":
        if state == "dirty":
            reason = "dirty-tree"
        elif state == "unsafe-config":
            reason = "unsafe-config"
        else:
            reason = "not-a-repo"
        return _result("refuse", reason, "none", None, "", "")
    try:
        data = read_matching_head(root, script)
    except ScriptRejected as exc:
        return _result("refuse", exc.reason, "none", None, "", "")
    digest = hashlib.sha256(data).hexdigest()
    if digest not in allowlist:
        return _result("refuse", "not-allowlisted", digest, None, "", "")
    completed = subprocess.run(
        child_command(),
        input=data,
        cwd=str(Path(os.path.realpath(root))),
        capture_output=True,
        env=child_env(),
        check=False,
        shell=False,
    )
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    return _result("allow", "ran", digest, completed.returncode, stdout, stderr)


def _result(
    decision: str,
    reason: str,
    digest: str,
    exit_code: int | None,
    stdout: str,
    stderr: str,
) -> dict[str, object]:
    return {
        "decision": decision,
        "reason": reason,
        "sha256": digest,
        "exit": "none" if exit_code is None else str(exit_code),
        "stdout": stdout,
        "stderr": stderr,
    }


def render_receipt(result: dict[str, object]) -> str:
    lines = [
        f"decision: {result['decision']}",
        f"reason: {result['reason']}",
        f"sha256: {result['sha256']}",
        f"exit: {result['exit']}",
        "stdout:",
        str(result["stdout"]),
        "stderr:",
        str(result["stderr"]),
    ]
    text = "\n".join(lines)
    if not text.endswith("\n"):
        text += "\n"
    return text


def redact(text: str, phrases: list[str] | None = None) -> str:
    return load_scrubber().scrub(text, phrases)


def open_receipt(path: Path) -> int:
    """Create a new regular file before the script starts. Do not follow a symlink."""
    if path.is_symlink():
        raise RunnerError("receipt is a symlink")
    if not path.parent.is_dir():
        raise RunnerError("receipt directory is missing")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        return os.open(path, flags, 0o644)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise RunnerError("receipt is a symlink") from exc
        if exc.errno == errno.EEXIST:
            raise RunnerError("receipt exists") from exc
        raise RunnerError("receipt could not be created") from exc


def write_receipt(fd: int, body: str) -> None:
    payload = body.encode("utf-8")
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written == 0:
            raise RunnerError("receipt could not be created")
        view = view[written:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a script only when its sha256 is allowlisted and the git tree is clean."
    )
    parser.add_argument("--allowlist", required=True, help="File of sha256 lines")
    parser.add_argument("--script", required=True, help="Script file to hash and maybe run")
    parser.add_argument("--receipt", required=True, help="Where to write the redacted receipt")
    parser.add_argument("--root", default=".", help="Git work tree to check. Defaults to the current directory.")
    parser.add_argument(
        "--phrases",
        default=None,
        help="Optional phrase file for the scrubber. When omitted, phrases.local.txt is used if it exists.",
    )
    args = parser.parse_args(argv)

    allowlist_path = Path(args.allowlist)
    script = Path(os.path.abspath(args.script))
    receipt_path = Path(args.receipt)
    root = Path(os.path.abspath(args.root))
    if not allowlist_path.is_file() or not root.is_dir():
        print("allowlist, script, or root is missing", file=sys.stderr)
        return 2
    # A final symlink is a policy refusal, not a missing file. exists() follows links.
    if not script.exists() and not script.is_symlink():
        print("allowlist, script, or root is missing", file=sys.stderr)
        return 2

    try:
        allowlist = parse_allowlist(allowlist_path.read_text(encoding="utf-8"))
        scrubber = load_scrubber()
        phrase_path = Path(args.phrases) if args.phrases else scrubber.DEFAULT_PHRASES
        if args.phrases and not phrase_path.is_file():
            print("phrase file is missing", file=sys.stderr)
            return 2
        phrases = scrubber.load_phrases(phrase_path)
        receipt_fd = open_receipt(receipt_path)
    except RunnerError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        result = decide(root, script, allowlist)
        body = scrubber.scrub(render_receipt(result), phrases)
        write_receipt(receipt_fd, body)
    except RunnerError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        os.close(receipt_fd)

    sys.stdout.write(body)
    if result["decision"] != "allow":
        return 1
    return 0 if result["exit"] == "0" else 1


if __name__ == "__main__":
    raise SystemExit(main())
