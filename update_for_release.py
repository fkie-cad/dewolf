import json
import re
import subprocess
import sys
import time
from pathlib import Path


def get_patch(tag: str, base: str) -> int:
    """Patch number of a same-day tag: ``v{base}`` -> 0, ``v{base}.N`` -> N."""
    suffix = tag[len(f"v{base}") :]
    return int(suffix[1:]) if suffix.startswith(".") else 0


def next_version(base: str) -> str:
    """Next version for today's ``base`` (``YYYY.M.D``), appending ``.N`` if it already exists."""
    process = subprocess.run(["git", "tag", "-l", f"v{base}", f"v{base}.*"], text=True, capture_output=True)
    existing = [line for line in process.stdout.splitlines() if line]
    if not existing:
        return base
    return f"{base}.{max(get_patch(tag, base) for tag in existing) + 1}"


def update_plugin_json(version: str) -> None:
    """Set the Binary Ninja plugin version."""
    path = Path("plugin.json")
    data = json.loads(path.read_text())
    data["version"] = version
    path.write_text(json.dumps(data, indent=4))


def update_pyproject(version: str) -> None:
    """Set the pip/pyproject version (identical to the tag, minus the leading ``v``).

    Skips quietly if pyproject.toml has no ``version`` field yet (e.g. before the packaging
    metadata lands), so the release workflow never fails over a not-yet-versioned pyproject.
    """
    path = Path("pyproject.toml")
    text = path.read_text()
    text, count = re.subn(r'(?m)^version = ".*"$', f'version = "{version}"', text, count=1)
    if count == 0:
        print("pyproject.toml has no version field yet; skipping", file=sys.stderr)
        return
    path.write_text(text)


if __name__ == "__main__":
    # Calendar version in PEP 440 / dotted form, so the tag `v<version>` equals the pip version.
    now = time.gmtime()
    new_version = next_version(f"{now.tm_year}.{now.tm_mon}.{now.tm_mday}")

    update_plugin_json(new_version)
    update_pyproject(new_version)

    # Print new version so the github action can use it
    print(new_version)
