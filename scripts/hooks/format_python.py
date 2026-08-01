#!/usr/bin/env python
"""PostToolUse hook: run `ruff format` on Python files as they are written.

CI checks formatting, so drift here means a red build for a reason unrelated to
the change. Formatting on write keeps that from ever reaching the pipeline.

Reads the hook payload on stdin. Always exits 0 — a formatter problem must never
block an edit, and a hook that can fail an edit is worse than no hook.
"""

from __future__ import annotations

import json
import subprocess
import sys


def target_path(payload: dict) -> str:
    """Pull the written file's path out of the hook payload."""
    response = payload.get("tool_response") or {}
    tool_input = payload.get("tool_input") or {}
    return response.get("filePath") or tool_input.get("file_path") or ""


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0

    path = target_path(payload)
    if path.endswith(".py"):
        subprocess.run(
            ["uv", "run", "ruff", "format", path],
            capture_output=True,
            check=False,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
