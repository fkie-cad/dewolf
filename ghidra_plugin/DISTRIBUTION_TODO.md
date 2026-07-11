# TODO — Ship the Ghidra plugin: pip-installable dewolf + double-click launcher

Status: **planned, not started.** Goal UX: `pip install "dewolf[ghidra]"` → run a one-time launcher
installer → **double-click a desktop icon (never a terminal)** and Ghidra opens with the dewolf window
already there. Updates via `pip install -U dewolf`.

## Decisions (settled)
- [x] **Distribution channel: PyPI** (`pip install dewolf`). No Ghidra "app store" exists; PyPI + pip is
  the closest equivalent and gives real `pip install -U` updates.
- [x] **Java plugin: compile-at-launch** via pyghidra's `install_plugin` (no Gradle zip, no CI matrix;
  always built against the running Ghidra; auto-reinstalls on source change).
- [x] **Launch: keep the in-process design + ship a double-click launcher** (Option A). Do NOT split
  into a sidecar.

## Verified facts (from Ghidra 12.1.2 source — don't re-litigate)
- dewolf calls Ghidra's Java API on the live `Program` object, so its CPython and Ghidra's JVM **must
  share one process** (JPype co-location). ⇒ launch must go through pyghidra (Python-hosts-JVM).
- **Stock `ghidraRun` cannot host CPython, and no config changes that.** Only pyghidra's launcher runs
  `setup_plugin()` (`launcher.py:490`); under plain `ghidraRun` the PyGhidra console prints *"Ghidra was
  not started with PyGhidra. Python is not available."* Hence the shipped desktop icon routes through
  pyghidra instead.
- pyghidra loads two entry-point groups on the GUI path (`GuiPyGhidraLauncher` inherits both):
  - `pyghidra.setup` → `callback(launcher)`, **before** `startJVM()` → call `launcher.install_plugin(...)`.
  - `pyghidra.pre_launch` → `callback()` (no args), **after** Ghidra init → register the backend.
- Today's `launch.py` already does both jobs (`install_plugin` `:87`, `_register_backend` `:47`); backend
  already handles "JVM already running" (`backend.py:399`). Migration is small.

---

## Phase 1 — Make dewolf pip-installable
- [ ] Add a real `[project]` table to root `pyproject.toml` (currently only black/isort config):
  `name = "dewolf"`, `requires-python = ">=3.10"`, version from `update_for_release.py` scheme.
- [ ] `dependencies` = runtime entries from `requirements.txt` (delogic, delogic-idioms, networkx, pydot,
  pygments, z3-solver). Move black/isort/pytest to `[project.optional-dependencies] dev`.
- [ ] `[project.optional-dependencies] ghidra = ["pyghidra"]` (frontend stays optional — matches
  `decompiler/frontend/__init__.py` try/except).
- [ ] setuptools packaging:
  - [ ] packages: `decompiler` (+subpackages), `ghidra_plugin` (+subpackages).
  - [ ] top-level module `decompile` (`py-modules = ["decompile"]`) — `backend.py:396` does
    `from decompile import Decompiler`, must import when installed.
  - [ ] **ship Java sources as package data**: `ghidra_plugin/java/**/*.java`
    (`[tool.setuptools.package-data]` / `include-package-data`). `install_plugin`/`javac` need real files
    on disk; wheels unpack, so `Path(__file__).parent/"java"` resolves.
- [ ] Do NOT package the repo-root `__init__.py` (BN plugin shim w/ `sys.path.append`); BN install stays
  git-clone-based.

## Phase 2 — pyghidra entry points
- [ ] New `ghidra_plugin/hooks.py` with two functions (shared by entry points + launcher):
  - [ ] `install_extension(launcher)` → `install_plugin(JAVA_SRC, ExtensionDetails(name="dewolf", ...,
    plugin_version=_plugin_version()))`. Reuse existing `_plugin_version()` sha1 hash (`launch.py:28`) —
    already drives auto-reinstall via pyghidra's `plugin_version` compare.
  - [ ] `register_backend()` → body of today's `_register_backend()` (`launch.py:47`);
    `DewolfBackendRegistry.setBackend(DewolfPythonBackend())`.
- [ ] Register in `pyproject.toml`:
  ```toml
  [project.entry-points."pyghidra.setup"]
  dewolf = "ghidra_plugin.hooks:install_extension"
  [project.entry-points."pyghidra.pre_launch"]
  dewolf = "ghidra_plugin.hooks:register_backend"
  ```

## Phase 3 — Console scripts + double-click launcher
- [ ] `[project.scripts] dewolf = "decompile:_cli"` — thin zero-arg CLI wrapper calling
  `commandline.main(Decompiler)`.
- [ ] `dewolf-ghidra` — the launch entry. Promote `launch.py:main()`: build `GuiPyGhidraLauncher`
  (install dir via `_resolve_install_dir`, `launch.py:36`), call `install_extension` + `register_backend`,
  then `launcher.start()`. Runs in dewolf's own interpreter (so plugin/backend match what's installed).
  Still works from a git checkout (where entry points aren't registered).
- [ ] `dewolf-install-launcher` — run once; new module `ghidra_plugin/desktop_launcher.py` creates the
  OS-native double-clickable entry pointing at the abs path of `dewolf-ghidra`
  (`shutil.which`/`sys.executable`):
  - [ ] **macOS**: minimal `dewolf.app` in `~/Applications` (`Contents/MacOS/dewolf` stub exec'ing
    `dewolf-ghidra`, `Info.plist`, icon). pyghidra already drives the Cocoa loop (`_run_mac_app`).
  - [ ] **Linux**: `~/.local/share/applications/dewolf-ghidra.desktop` (`Exec=<abs>`, `Terminal=false`,
    icon).
  - [ ] **Windows**: Start-menu / Desktop `.lnk` (PowerShell `WScript.Shell` or `pywin32`).
  - [ ] Bake `GHIDRA_INSTALL_DIR` into the entry (or leave to runtime autodetect).

## Phase 4 — Docs + release
- [ ] Rewrite `ghidra_plugin/README.md` + main install docs: `pip install "dewolf[ghidra]"` → run
  `dewolf-install-launcher` once → double-click the icon. Note: `astyle` is an external system dep
  (degrades gracefully, `backend.py:385`); dewolf must be installed in the interpreter the launcher uses
  (the shipped launcher guarantees this).
- [ ] GitHub Actions: build wheel + publish to PyPI on tag (trusted publishing); run headless smoke test
  as a gate.

---

## Files to touch
- `pyproject.toml` (root) — `[project]`, deps, packaging, entry points, 3 console scripts.
- `ghidra_plugin/hooks.py` (new) — `install_extension` / `register_backend`.
- `ghidra_plugin/desktop_launcher.py` (new) — per-OS launcher generation.
- `ghidra_plugin/launch.py` — `main()` becomes `dewolf-ghidra`, delegates to `hooks.py`.
- `ghidra_plugin/backend.py` — no logic change; verify `from decompile import Decompiler` (`:396`) and
  the Java package-data path resolve when installed.
- `decompile.py` / `decompiler/util/commandline.py` — `_cli` wrapper.
- `ghidra_plugin/README.md` + main README — new instructions.
- `requirements.txt` — source of truth for deps (or superseded by pyproject).

## Verification
- [ ] `python -m build`; `unzip -l dist/*.whl` shows `ghidra_plugin/java/**.java` + top-level `decompile.py`.
- [ ] Fresh venv `pip install "dist/dewolf-*.whl[ghidra]"`; `import decompiler, ghidra_plugin, decompile`
  works; `dewolf` / `dewolf-ghidra` / `dewolf-install-launcher` scripts exist.
- [ ] Entry points present:
  `python -c "import importlib.metadata as m; print([(e.group,e.name,e.value) for g in ('pyghidra.setup','pyghidra.pre_launch') for e in m.entry_points(group=g)])"`
- [ ] `dewolf-install-launcher` creates the OS entry (e.g. `~/Applications/dewolf.app`) → points at
  `dewolf-ghidra` abs path.
- [ ] **Acceptance test**: double-click the icon (no terminal) → Ghidra opens, dewolf window present and
  follows the cursor.
- [ ] Touch a `.java` source → relaunch → pyghidra uninstalls old `dewolf` extension, installs new.
- [ ] Run existing `smoke_test.py` against the installed package (not repo cwd) — import resolution no
  longer depends on repo root.
- [ ] `pip install -U` newer build → relaunch via same icon shows new version, no manual Ghidra steps.
