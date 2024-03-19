import json
import subprocess
import time
from pathlib import Path


def get_patch(line: str) -> int:
    return int(line[index + 1 :]) if (index := line.rfind(".")) != -1 else 0


if __name__ == "__main__":
    new_version = time.strftime("%Y-%m-%d")

    process = subprocess.run(["git", "tag", "-l", f"v{new_version}*"], text=True, capture_output=True)
    patch = max((get_patch(line) for line in process.stdout.splitlines()), default=None)

    if patch is not None:
        new_version += f".{patch + 1}"

    release_path = Path("plugin.json")
    with release_path.open("r") as file:
        data = json.load(file)

    data["version"] = new_version

    with release_path.open("w") as file:
        json.dump(data, file, indent=4)

    # Print new version so the github action can use it
    print(new_version)
