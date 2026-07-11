# TODO — Ship the Ghidra plugin: pip-installable dewolf + double-click launcher

Status: **All phases done & verified (PyPI publish deferred). Remaining: real-Ghidra GUI smoke test + commit.** Goal UX:
`pip install "dewolf[ghidra] @ git+https://github.com/fkie-cad/dewolf.git"` → run a one-time launcher
installer → **double-click a desktop icon (never a terminal)** and Ghidra opens with the dewolf window
already there. Updates by re-installing the git ref.

## Decisions (settled)
- [x] **Distribution channel: install from the GitHub URL** (`pip install
  "dewolf[ghidra] @ git+https://github.com/fkie-cad/dewolf.git"`). PyPI is deferred — the packaging work
  is identical either way; only PyPI publishing + owning the name are skipped. Pin with `@<tag>`/`@<commit>`;
  update by re-installing the ref. Bonus: installing from git allows **direct-URL deps** (PyPI forbids
  them), so dewolf's own git deps (`delogic`, `dewolf-idioms`) can be `pkg @ git+https://…` in
  `[project.dependencies]`.
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

## Phase 1 — Make dewolf pip-installable  ✅ DONE (verified via built wheel + fresh-venv install)
- [x] Added `[build-system]` + `[project]` to root `pyproject.toml`: `name = "dewolf"`,
  `requires-python = ">=3.10"`, static `version = "0.1.0"` (release-time date versioning stays in
  `update_for_release.py`/`plugin.json`, separate from the pip version).
- [x] `dependencies` from `requirements.txt`, with git deps as **direct URLs** (legal off-PyPI):
  `delogic @ git+…/dewolf-logic.git`, `compiler-idioms @ git+…/dewolf-idioms.git`
  (NB: the idioms **dist name is `compiler-idioms`**, confirmed via `packages_distributions`, not
  "dewolf-idioms"), plus `networkx != 2.8.4`, `pydot`, `pygments`, `z3-solver == 4.8.10`.
  black/isort/pytest moved to `[project.optional-dependencies] dev`.
- [x] `[project.optional-dependencies] ghidra = ["pyghidra"]` (frontend stays optional).
- [x] setuptools packaging: `packages.find include = ["decompiler*","ghidra_plugin*"]`,
  `py-modules = ["decompile"]`, `package-data ghidra_plugin = ["java/**/*.java"]` (the `**` glob works —
  13 `.java` files land under `site-packages/ghidra_plugin/java/…` on install).
- [x] Repo-root `__init__.py` (BN shim), `tests/`, `dewolf-idioms/` are NOT packaged (verified absent
  from the wheel). BN install stays git-clone-based.
- [x] `dewolf` CLI wired: added `_cli()` to `decompile.py`; `[project.scripts] dewolf = "decompile:_cli"`.
- [x] `dewolf-ghidra` CLI wired to the existing `ghidra_plugin.launch:main` (works today; will move to the
  `hooks.py` refactor in Phase 2).

## Phase 2 — pyghidra entry points  ✅ DONE (verified: entry_points.txt in built wheel)
- [x] New `ghidra_plugin/hooks.py` with `plugin_version()`, `install_extension(launcher)` (the
  `pyghidra.setup` hook), `register_backend()` (the `pyghidra.pre_launch` hook). Lazy imports so the
  module loads without pyghidra/a JVM.
- [x] `launch.py` refactored to import + call these hooks (single code path shared with the entry
  points); removed the duplicated `_plugin_version`/`_register_backend`.
- [x] Registered both entry points in `pyproject.toml` (`pyghidra.setup`/`pyghidra.pre_launch` → the two
  hooks). Confirmed present in the wheel's `entry_points.txt`.

## Phase 3 — Console scripts + double-click launcher  ✅ DONE (verified: built wheel + sandboxed run)
- [x] `dewolf` (`decompile:_cli`) and `dewolf-ghidra` (`ghidra_plugin.launch:main`) console scripts.
- [x] `dewolf-install-launcher` (`ghidra_plugin.desktop_launcher:main`) — generates the OS-native
  double-click launcher. Prefers the installed `dewolf-ghidra` script (checked on PATH + next to the
  interpreter), falls back to `python -m ghidra_plugin`. Bakes `GHIDRA_INSTALL_DIR` when set, else
  leaves it to runtime autodetect.
  - [x] **macOS**: `~/Applications/dewolf.app` (`Contents/MacOS/dewolf` bash stub + `Info.plist`).
    Verified end-to-end with a sandboxed `HOME` (bundle + stub generated correctly).
  - [x] **Linux**: `~/.local/share/applications/dewolf-ghidra.desktop` (`Terminal=false`).
  - [x] **Windows**: Desktop `.lnk` via PowerShell `WScript.Shell`; uses a generated `.cmd` wrapper when
    env baking / extra args are needed (a `.lnk` can't set env vars). *(code path not runtime-verified on
    macOS dev box — no Windows to test on.)*

## Phase 4 — Docs  ✅ DONE
- [x] Rewrote `ghidra_plugin/README.md`: pip-from-git install, the three console scripts, double-click
  launcher / terminal / `pyghidraRun` routes, the same-interpreter requirement, and the `astyle` note.
- [x] Added a "Ghidra Plugin" section to the main `README.md` pointing at `ghidra_plugin/README.md`.
- [ ] (Deferred) PyPI publish + trusted-publishing CI job — not needed for git-URL installs. Revisit later.

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
- [ ] Fresh venv, install straight from git:
  `pip install "dewolf[ghidra] @ git+file://$(pwd)"` (local clone) or the GitHub URL. Confirm
  `import decompiler, ghidra_plugin, decompile` works and `dewolf` / `dewolf-ghidra` /
  `dewolf-install-launcher` scripts exist. (Also sanity-check `pip wheel` builds and the wheel contains
  `ghidra_plugin/java/**.java` + top-level `decompile.py` — proves package-data is shipped.)
- [ ] Entry points present:
  `python -c "import importlib.metadata as m; print([(e.group,e.name,e.value) for g in ('pyghidra.setup','pyghidra.pre_launch') for e in m.entry_points(group=g)])"`
- [ ] `dewolf-install-launcher` creates the OS entry (e.g. `~/Applications/dewolf.app`) → points at
  `dewolf-ghidra` abs path.
- [ ] **Acceptance test**: double-click the icon (no terminal) → Ghidra opens, dewolf window present and
  follows the cursor.
- [ ] Touch a `.java` source → relaunch → pyghidra uninstalls old `dewolf` extension, installs new.
- [ ] Run existing `smoke_test.py` against the installed package (not repo cwd) — import resolution no
  longer depends on repo root.
- [ ] Re-install a newer git ref (`pip install --force-reinstall "… @ git+…@<tag>"`) → relaunch via same
  icon shows new version, no manual Ghidra steps.
