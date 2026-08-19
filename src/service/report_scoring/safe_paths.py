import stat
from pathlib import Path


class UnsafePathError(ValueError):
    pass


def is_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def resolve_path_within_root(
    path: Path,
    root: Path,
    *,
    strict: bool,
) -> Path:
    """Resolve a path while rejecting every symlink/junction in its root-relative chain."""

    root_resolved = root.resolve(strict=True)
    candidate = path if path.is_absolute() else root_resolved / path
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise UnsafePathError("path is outside the configured root") from exc

    cursor = candidate
    while True:
        if is_reparse_point(cursor):
            raise UnsafePathError("path contains a symlink or reparse point")
        if cursor == root_resolved:
            break
        cursor = cursor.parent

    try:
        resolved = candidate.resolve(strict=strict)
        resolved.relative_to(root_resolved)
    except (OSError, RuntimeError, ValueError) as exc:
        raise UnsafePathError("path cannot be resolved inside the configured root") from exc
    return resolved
