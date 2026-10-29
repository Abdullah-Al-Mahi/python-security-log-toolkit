"""Local, non-destructive Git publication preflight (not a full secret scanner)."""
from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

SENSITIVE_NAMES = {".env", ".env.local", "id_rsa", "id_ed25519", "credentials.json", "secrets.yaml"}
SENSITIVE_SUFFIXES = {".pem", ".p12", ".pfx", ".key", ".sqlite", ".sqlite3", ".db", ".evtx"}
SENSITIVE_DIRS = {".venv", "venv", "__pycache__", "private", "secrets", ".pytest_cache"}
SECRET_PATTERNS = {
    "private-key header": re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|ENCRYPTED) PRIVATE KEY-----"),
    "GitHub token-shaped value": re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    "AWS access key-shaped value": re.compile(r"AKIA[A-Z0-9]{16}"),
    "API key-shaped value": re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{24,}"),
}
TEXT_SUFFIXES = {".py", ".md", ".txt", ".yaml", ".yml", ".toml", ".json", ".xml", ".log", ".mmd", ".gitignore", ".gitattributes"}


def tracked_paths(root: Path) -> list[str]:
    """Use Git's index rather than scanning ignored or private working files."""
    proc = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=False)
    if proc.returncode:
        raise ValueError("Git is unavailable or this directory is not a Git repository")
    return [item.decode("utf-8", errors="surrogateescape") for item in proc.stdout.split(b"\0") if item]


def audit_paths(root: Path, paths: list[str]) -> list[str]:
    """Return issues without revealing any potential secret value itself."""
    root = root.resolve()
    issues = []
    for pathstr in sorted(set(paths)):
        relative = PurePosixPath(pathstr.replace("\\", "/"))
        if relative.is_absolute() or ".." in relative.parts:
            issues.append(f"{pathstr}: unsafe tracked path")
            continue
        path = root.joinpath(*relative.parts)
        if not path.exists():
            continue  # staged deletion
        if path.is_symlink():
            issues.append(f"{pathstr}: review tracked symbolic link")
            continue
        if not path.is_file():
            continue
        # Preserve an empty Git placeholder for the reports directory. This
        # exact zero-byte file carries no report data; all other files in
        # reports/, including a nonempty .gitkeep, remain audit findings.
        if relative.as_posix() == "reports/.gitkeep" and path.stat().st_size == 0:
            continue
        if (relative.parts and relative.parts[0].lower() == "reports") or any(part.lower() in SENSITIVE_DIRS for part in relative.parts[:-1]):
            issues.append(f"{pathstr}: generated/private directory is tracked")
        if relative.name.lower() in SENSITIVE_NAMES or (relative.suffix.lower() in SENSITIVE_SUFFIXES):
            issues.append(f"{pathstr}: potentially sensitive file is tracked")
        if path.stat().st_size > 2 * 1024 * 1024:
            issues.append(f"{pathstr}: file exceeds 2 MiB; review before publishing")
        if path.suffix.lower() not in TEXT_SUFFIXES and relative.name not in {".gitignore", ".gitattributes"}:
            continue
        if path.stat().st_size > 2 * 1024 * 1024:
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        for description, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                issues.append(f"{pathstr}: {description} detected; inspect locally")
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit Git-tracked files locally before publication")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        paths = tracked_paths(args.root)
        issues = audit_paths(args.root, paths)
    except (ValueError, OSError) as exc:
        print(f"Audit error: {exc}", file=sys.stderr)
        return 2
    print(f"Inspected {len(paths)} tracked file paths (offline; no uploads).")
    if issues:
        for issue in issues:
            print(f"REVIEW: {issue}")
        print(f"Result: REVIEW NEEDED ({len(issues)} issue(s)); do not publish yet")
        return 1
    print("Result: no listed risk indicators found; manual privacy/history review still required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
