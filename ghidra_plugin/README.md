# dewolf in the Ghidra GUI

A dockable **"dewolf Decompiler"** window for Ghidra, analogous to the built-in
Decompiler window: it follows the cursor in the Listing and shows dewolf's
decompilation of the current function.

dewolf runs *in-process*: Ghidra is started through PyGhidra, so the Ghidra GUI
(JVM) and dewolf (CPython) share one process and one `Program` object — no export,
RPC, or serialization involved. Decompilation uses dewolf's Ghidra frontend
(High-P-code lifting) directly on the program open in the CodeBrowser.

## Requirements

- Ghidra 11.3+ (with the bundled PyGhidra feature); tested with 12.1.2
- the dewolf virtualenv with `pyghidra` installed (same setup as `--frontend ghidra`)

## Usage

From the dewolf repository:

```sh
python -m ghidra_plugin                      # auto-detects the Ghidra install
python -m ghidra_plugin --install-dir /path/to/ghidra_12.1.2_PUBLIC
```

(`GHIDRA_INSTALL_DIR` is honored as well.)

This launches the normal Ghidra GUI. On the first launch the Java plugin under
`ghidra_plugin/java/` is compiled and installed automatically as a Ghidra
extension named `dewolf` (recompiled whenever the Java source changes).

**First run only:** when you open the CodeBrowser tool, Ghidra asks whether to
configure newly detected plugins — confirm and enable *DewolfGhidraPlugin*
(alternatively: *File → Configure → Configure All Plugins*). The window is then
available under *Window → dewolf Decompiler* and its docking position is saved
with the tool.

## Behavior

- **Follow cursor** (toolbar toggle): decompiles the function containing the
  cursor, debounced like the built-in decompiler.
- **Refresh** (toolbar button): forces re-decompilation of the current function.
- Results are cached per function and invalidated automatically on any program
  database change (renames, retypes, ...), since the cache key includes the
  program's modification number.
- Decompilation errors are shown as comments in the code view instead of crashing
  the tool.

If Ghidra is started without dewolf (plain `ghidraRun`), the window shows a hint
instead; the plugin itself stays inert.

## Configuration

dewolf's options are exposed in Ghidra's native settings under
*Edit → Tool Options → dewolf* (grouped by dewolf's option categories, e.g.
*Readability*, *Miscellaneous*). Changing an option re-decompiles the current
function immediately. This mirrors the Binary Ninja plugin, which surfaces the same
options in BN's settings; both are driven from `decompiler/util/default.json`
(options marked `is_hidden_from_gui` are not shown).

## Layout

- `java/dewolfghidra/` — the Ghidra plugin (`DewolfGhidraPlugin`, `DewolfProvider`)
  and the `DewolfBackend` bridge interface with its registry. Compiled at launch
  time by pyghidra; no Gradle needed.
- `backend.py` — implements `DewolfBackend` in Python (JPype `@JImplements`),
  wrapping `Decompiler.from_raw(program, frontend="ghidra")` with per-program
  frontend reuse and an LRU result cache.
- `launch.py` / `__main__.py` — the launcher: installs the extension, registers
  the backend, starts the GUI.
