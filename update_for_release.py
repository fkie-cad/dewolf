import json
import time
from pathlib import Path

if __name__ == "__main__":
    release_path = Path("plugin.json")
    with release_path.open("r") as file:
        data = json.load(file)

    old_version: str = data["version"]
    new_version = time.strftime("%Y-%m-%d")

    if old_version.startswith(new_version):
        patch = int(old_version[index + 1:]) if (index := old_version.rfind(".")) != -1 else 0
        new_version += f".{patch + 1}"

    data["version"] = new_version

    with release_path.open("w") as file:
        json.dump(data, file, indent=4)

    # Print new version so the github action can use it
    print(new_version)
