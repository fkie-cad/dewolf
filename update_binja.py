import binaryninja

current_version = binaryninja.core_version()
print("Looking for BinaryNinja Updates...")
channel = binaryninja.update.UpdateChannel("release", None, current_version)
latest_version = channel.versions[0]
if channel.updates_available:
    print(f"There is an Update available: {latest_version}. Updating from {current_version} to {latest_version}...")
    try:
        latest_version.update()
        if binaryninja.update.is_update_installation_pending():
            binaryninja.update.install_pending_update()
    except:
        pass
    print("Finished Installation.")
else:
    print(f"The installed version {latest_version} is already the newest.")
