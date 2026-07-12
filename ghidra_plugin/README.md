# dewolf in the Ghidra GUI

A dockable **"dewolf Decompiler"** window for Ghidra, analogous to the built-in
Decompiler window: it follows the cursor in the Listing and shows dewolf's
decompilation of the current function.

dewolf runs *in-process*: Ghidra is started through PyGhidra, so the Ghidra GUI
(JVM) and dewolf (CPython) share one process and one `Program` object — no export,
RPC, or serialization involved. Decompilation uses dewolf's Ghidra frontend
(High-P-code lifting) directly on the program open in the CodeBrowser.

Because dewolf is CPython, it can share Ghidra's `Program` only when Ghidra is
launched **through PyGhidra** (Python hosts the JVM). Plain `ghidraRun` has no
Python interpreter, so the launchers below all go through PyGhidra.

## Requirements

- Ghidra 11.3+ (with the bundled PyGhidra feature); tested with 12.1.2
- Python 3.10+ (indentation uses `clang-format`, pulled in automatically by `pip install "dewolf[ghidra]"`)

## Install

Install dewolf (with the `ghidra` extra) into the Python interpreter you will launch
Ghidra with:

```sh
pip install "dewolf[ghidra] @ git+https://github.com/fkie-cad/dewolf.git"
```

Pin a release by appending `@v2026.7.11` (or any tag/branch/commit). This provides three
console scripts: `dewolf` (CLI), `dewolf-ghidra` (GUI launcher) and `dewolf-install-launcher`.

> dewolf must live in the same interpreter that launches Ghidra. The launchers below run
> in dewolf's own interpreter, so this is handled for you.

## Usage

### Double-click launcher (recommended)

Create an OS-native launcher once, then open Ghidra-with-dewolf from a normal desktop
icon — no terminal:

```sh
dewolf-install-launcher                        # optionally: --ghidra-install-dir /path/to/ghidra
```

This writes a macOS `dewolf.app` (in `~/Applications`), a Linux `.desktop` entry, or a
Windows `.lnk`, pointing at `dewolf-ghidra`. If `GHIDRA_INSTALL_DIR` is set when you run
it, that path is baked into the launcher; otherwise dewolf autodetects Ghidra at launch.
Then double-click **dewolf for Ghidra**.

### From a terminal

```sh
dewolf-ghidra                                  # auto-detects the Ghidra install
dewolf-ghidra --install-dir /path/to/ghidra_12.1.2_PUBLIC
```

(`GHIDRA_INSTALL_DIR` is honored as well. From a source checkout, `python -m ghidra_plugin`
is equivalent.)

### From Ghidra's own PyGhidra launcher

If dewolf is installed in the interpreter `pyghidraRun` uses, it activates automatically via
its `pyghidra.setup` / `pyghidra.pre_launch` entry points — no extra step.

---

All three routes launch the normal Ghidra GUI. On the first launch the Java plugin under
`ghidra_plugin/java/` is compiled and installed automatically as a Ghidra extension named
`dewolf` (recompiled whenever the Java source changes).

**First run only:** when you open the CodeBrowser tool, Ghidra asks whether to configure newly
detected plugins — confirm and enable *DewolfGhidraPlugin* (alternatively: *File → Configure →
Configure All Plugins*). The window is then available under *Window → dewolf Decompiler* and its
docking position is saved with the tool.

## Behavior

- **Follow cursor** (toolbar toggle): decompiles the function containing the cursor, debounced
  like the built-in decompiler.
- **Refresh** (toolbar button): forces re-decompilation of the current function.
- Results are cached per function and invalidated automatically on any program database change
  (renames, retypes, ...), since the cache key includes the program's modification number.
- Decompilation errors are shown as comments in the code view instead of crashing the tool.

If Ghidra is started without dewolf (plain `ghidraRun`), the window shows a hint instead; the
plugin itself stays inert.

## Configuration

dewolf's options are exposed in Ghidra's native settings under *Edit → Tool Options → dewolf*
(grouped by dewolf's option categories, e.g. *Readability*, *Miscellaneous*). Changing an option
re-decompiles the current function immediately. This mirrors the Binary Ninja plugin, which
surfaces the same options in BN's settings; both are driven from `decompiler/util/default.json`
(options marked `is_hidden_from_gui` are not shown).

## Layout

- `java/dewolfghidra/` — the Ghidra plugin (`DewolfGhidraPlugin`, `DewolfProvider`) and the
  `DewolfBackend` bridge interface with its registry. Compiled at launch time by pyghidra; no
  Gradle needed.
- `backend.py` — implements `DewolfBackend` in Python (JPype `@JImplements`), wrapping
  `Decompiler.from_raw(program, frontend="ghidra")` with per-program frontend reuse and an LRU
  result cache.
- `hooks.py` — the `pyghidra.setup` (install the extension) and `pyghidra.pre_launch` (register
  the backend) hooks, exposed as entry points and reused by `launch.py`.
- `launch.py` / `__main__.py` — the `dewolf-ghidra` launcher: builds a `GuiPyGhidraLauncher` and
  calls the hooks, then starts the GUI.
- `desktop_launcher.py` — the `dewolf-install-launcher` script that generates the per-OS
  double-click launcher.
