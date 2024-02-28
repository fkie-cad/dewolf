import json
from pathlib import Path

if __name__ == "__main__":
    release_path = Path("plugin.json")
    with release_path.open("r") as file:
        data = json.load(file)

    # Assuming the version string follows the "major.minor.patch" format
    version_parts = data["version"].split(".")
    major, minor, patch = map(int, version_parts)

    # Increment the patch version
    patch += 1

    # Update the version in the data
    new_version = f"{major}.{minor}.{patch}"
    data["version"] = new_version

    with release_path.open("w") as file:
        json.dump(data, file, indent=4)

    # Print new version so the github action can use it
    print(new_version)
