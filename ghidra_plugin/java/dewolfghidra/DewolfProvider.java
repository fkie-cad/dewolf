package dewolfghidra;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import docking.widgets.dialogs.InputDialog;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.component.DecompilerCallbackHandlerAdapter;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.EmptyDecompileData;
import ghidra.app.decompiler.component.LocationClangHighlightController;
import ghidra.app.services.GoToService;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import resources.Icons;

/**
 * Dockable window showing dewolf's decompilation of the current function.
 *
 * Rendering uses the built-in DecompilerPanel driven through
 * DecompilerController.setDecompileData() with a token tree synthesized from dewolf's
 * output (the in-tree precedent is CodeCompare's CDisplay). setDecompileData never
 * touches the native decompiler process — only controller.display() would. Since the
 * involved classes are internal API, any failure to set up the panel falls back to a
 * plain styled text view.
 */
public class DewolfProvider extends ComponentProviderAdapter {

	private static final String NO_BACKEND_TEXT =
		"// dewolf backend is not connected.\n" +
		"//\n" +
		"// Ghidra was started without dewolf. To use this window, launch Ghidra through\n" +
		"// dewolf's PyGhidra launcher from the dewolf repository:\n" +
		"//\n" +
		"//     python -m ghidra_plugin\n";

	private static final String WELCOME_TEXT =
		"// dewolf decompiler\n" +
		"//\n" +
		"// Click into a function in the Listing to decompile it.\n";

	private final DewolfGhidraPlugin plugin;
	private final JPanel panel = new JPanel(new BorderLayout());
	private final JLabel statusLabel = new JLabel(" ");
	// Single worker: dewolf's frontend/DecompInterface is not thread-safe, so at most one
	// decompilation runs at a time. A priority queue lets a foreground navigation (priority 0)
	// jump ahead of any queued background prefetch (priority 1); only an already-running prefetch
	// can delay it, and it cannot be cancelled mid-run.
	private final ThreadPoolExecutor executor = new ThreadPoolExecutor(1, 1, 0L,
		TimeUnit.MILLISECONDS, new PriorityBlockingQueue<>(), runnable -> {
			Thread thread = new Thread(runnable, "dewolf-decompile");
			thread.setDaemon(true);
			return thread;
		});
	private final AtomicLong requestCounter = new AtomicLong();
	private final AtomicLong taskSequence = new AtomicLong();

	// DecompilerPanel rendering; null when it failed and the fallback view is active
	private DecompilerController controller;
	private DecompileOptions decompileOptions;
	private Program optionsProgram;
	// fallback rendering, always constructed so a renderer failure can never leave
	// the window without a working view
	private JTextPane codeArea;
	private JComponent fallbackComponent;

	private boolean followCursor = true;
	private Program displayedProgram;
	private Function displayedFunction;
	private Address displayedEntry;
	private long displayedModNumber = -1;
	private DewolfDecompilation currentDecompilation;
	// Back-navigation history (Esc), mirroring the built-in decompiler's NavigationHistory.
	private final Deque<HistoryEntry> history = new ArrayDeque<>();
	private static final int HISTORY_LIMIT = 100;
	private boolean suppressHistory; // while navigating back via Esc
	// set while an in-place rename/retype is committing, so the resulting program-change
	// event does not trigger a full (slow) re-decompile
	private boolean suppressNextRefresh;
	// Most recently rendered decompilation per (program, entry), so Esc / revisits restore a
	// previously shown function instantly on the Swing thread instead of queueing behind an
	// in-flight decompilation on the single background thread (dewolf can be slow).
	//
	// Access-order (LRU), not insertion-order: every get()/put() marks an entry recently-used, so
	// the function you are looking at and the ones you recently viewed survive eviction. The cap is
	// >= PREFETCH_LIMIT so a whole background prefetch sweep cannot evict your foreground working set
	// (the old insertion-order cap of 100 was smaller than the 500-function prefetch reach, so
	// prefetch churned out functions you had actually visited -> revisiting re-decompiled them).
	private static final int RENDER_CACHE_LIMIT = 512;
	private final java.util.LinkedHashMap<HistoryEntry, Rendered> rendered =
		new java.util.LinkedHashMap<>(64, 0.75f, true) {
			@Override
			protected boolean removeEldestEntry(java.util.Map.Entry<HistoryEntry, Rendered> e) {
				return size() > RENDER_CACHE_LIMIT;
			}
		};

	// View-only renames (identifier -> new name), per function, for variables that have no backing
	// database symbol. Re-applied on every re-decompile so they persist for the session.
	private final java.util.Map<HistoryEntry, java.util.LinkedHashMap<String, String>> viewRenames =
		new java.util.HashMap<>();

	// Background prefetch: after a function is shown, decompile its callees breadth-first (then any
	// other not-yet-cached function) so navigating to them is instant. All bookkeeping below runs on
	// the Swing thread; only the decompile itself is handed to the worker. A generation counter
	// supersedes stale prefetch work whenever a new function is displayed.
	private final java.util.ArrayDeque<Address> prefetchQueue = new java.util.ArrayDeque<>();
	private final java.util.Set<Address> prefetchEnqueued = new java.util.HashSet<>();
	private final java.util.Set<Address> prefetchDone = new java.util.HashSet<>();
	private long prefetchDoneModNumber = -1; // database version prefetchDone was collected at
	private final AtomicLong prefetchGeneration = new AtomicLong();
	private int prefetchCount; // decompiles issued for the current seed, capped by PREFETCH_LIMIT
	private static final int PREFETCH_LIMIT = 500;

	private record HistoryEntry(Program program, Address entry) {
	}

	/** A queued decompilation; foreground (priority 0) is dequeued before prefetch (priority 1). */
	private static final class PrioritizedTask implements Runnable, Comparable<PrioritizedTask> {
		private final int priority;
		private final long sequence;
		private final Runnable body;

		PrioritizedTask(int priority, long sequence, Runnable body) {
			this.priority = priority;
			this.sequence = sequence;
			this.body = body;
		}

		@Override
		public void run() {
			body.run();
		}

		@Override
		public int compareTo(PrioritizedTask other) {
			int byPriority = Integer.compare(priority, other.priority);
			return byPriority != 0 ? byPriority : Long.compare(sequence, other.sequence);
		}
	}

	/** A database mutation that may throw a checked exception (rename/retype commit). */
	private interface Commit {
		void run() throws Exception;
	}

	private record Rendered(DewolfDecompilation decompilation, long modificationNumber) {
	}

	public DewolfProvider(DewolfGhidraPlugin plugin) {
		super(plugin.getTool(), "dewolf Decompiler", plugin.getName());
		this.plugin = plugin;
		buildPanel();
		setTitle("dewolf Decompiler");
		setWindowMenuGroup("dewolf");
		setDefaultWindowPosition(WindowPosition.WINDOW);
		createActions();
		addToTool();
	}

	private void buildPanel() {
		fallbackComponent = buildFallbackTextPane();
		JComponent center = fallbackComponent;
		try {
			center = buildDecompilerPanel();
		}
		catch (Throwable t) {
			Msg.error(this, "dewolf: DecompilerPanel setup failed, using plain text view", t);
			controller = null;
		}
		statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
		panel.add(center, BorderLayout.CENTER);
		panel.add(statusLabel, BorderLayout.SOUTH);
		showMessage(WELCOME_TEXT);
	}

	private JComponent buildDecompilerPanel() {
		decompileOptions = new DecompileOptions();
		DecompilerCallbackHandlerAdapter handler = new DecompilerCallbackHandlerAdapter() {
			@Override
			public void locationChanged(ProgramLocation programLocation) {
				navigateTo(programLocation);
			}
		};
		controller = new DecompilerController(tool, handler, decompileOptions, null);
		// the panel dereferences its highlight controller unguarded (e.g. in
		// optionsChanged); the built-in DecompilerProvider installs exactly this one
		controller.getDecompilerPanel()
				.setHighlightController(new LocationClangHighlightController());
		controller.setMouseNavigationEnabled(true);
		docking.widgets.fieldpanel.FieldPanel fieldPanel =
			controller.getDecompilerPanel().getFieldPanel();
		// the panel's own double-click navigation only understands decoder-built token
		// types (ClangFuncNameToken etc.); ours navigate by their carried address
		fieldPanel.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent event) {
				// FieldPanel moves the caret only on left-click, so a right-click (popup)
				// would leave getTokenAtCursor() pointing at the previous token, breaking
				// the rename actions. Move the caret to the clicked token first.
				if (event.isPopupTrigger() || event.getButton() == MouseEvent.BUTTON3) {
					moveCaretTo(event);
				}
			}

			@Override
			public void mouseReleased(MouseEvent event) {
				if (event.isPopupTrigger()) {
					moveCaretTo(event);
				}
			}

			@Override
			public void mouseClicked(MouseEvent event) {
				if (event.getClickCount() == 2 && event.getButton() == MouseEvent.BUTTON1) {
					navigateToTokenAtCursor();
				}
			}
		});
		return controller.getDecompilerPanel();
	}

	private void moveCaretTo(MouseEvent event) {
		if (controller == null) {
			return;
		}
		docking.widgets.fieldpanel.FieldPanel fieldPanel =
			controller.getDecompilerPanel().getFieldPanel();
		docking.widgets.fieldpanel.support.FieldLocation location =
			fieldPanel.getLocationForPoint(event.getX(), event.getY());
		if (location != null) {
			fieldPanel.setCursorPosition(location.getIndex(), location.getFieldNum(),
				location.getRow(), location.getCol());
		}
	}

	private JComponent buildFallbackTextPane() {
		codeArea = new JTextPane() {
			@Override
			public boolean getScrollableTracksViewportWidth() {
				// disable line wrapping: only track the viewport when we are narrower
				return getUI().getPreferredSize(this).width <= getParent().getWidth();
			}
		};
		codeArea.setEditable(false);
		codeArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
		codeArea.setBackground(CSyntaxHighlighter.BACKGROUND);
		codeArea.setForeground(CSyntaxHighlighter.FOREGROUND);
		codeArea.setCaretColor(CSyntaxHighlighter.FOREGROUND);
		return new JScrollPane(codeArea);
	}

	private void navigateTo(ProgramLocation programLocation) {
		if (programLocation == null || displayedProgram == null) {
			return;
		}
		// single-click/cursor sync stays inside the current function (like the built-in
		// decompiler); leaving the function is reserved for an explicit double-click
		Address address = programLocation.getAddress();
		if (address != null && displayedFunction != null &&
			!displayedFunction.getBody().contains(address)) {
			return;
		}
		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			goToService.goTo(programLocation, displayedProgram);
		}
	}

	/**
	 * Double-click: for a function token, switch the window to that function; for a data
	 * reference (global) token, navigate the Listing to the data so its contents are visible.
	 */
	private void navigateToTokenAtCursor() {
		if (controller == null || displayedProgram == null) {
			return;
		}
		ClangToken token = controller.getDecompilerPanel().getTokenAtCursor();
		Function target = resolveFunction(token);
		if (target != null) {
			GoToService goToService = tool.getService(GoToService.class);
			if (goToService != null) {
				goToService.goTo(new ProgramLocation(displayedProgram, target.getEntryPoint()),
					displayedProgram);
			}
			// imports/thunks have no body to decompile; navigating the Listing is all we can do
			if (target.isExternal() || target.isThunk()) {
				statusLabel.setText("dewolf: '" + target.getName() + "' is an imported function");
				return;
			}
			// switch the window directly rather than relying on the location-event round trip
			showFunction(displayedProgram, target, true);
			return;
		}
		// data reference: jump the Listing to the data location so its contents are visible
		Address dataAddress = token == null ? null : token.getMinAddress();
		if (dataAddress != null) {
			GoToService goToService = tool.getService(GoToService.class);
			if (goToService != null) {
				goToService.goTo(new ProgramLocation(displayedProgram, dataAddress),
					displayedProgram);
				statusLabel.setText("dewolf: jumped to " + dataAddress);
				return;
			}
		}
		statusLabel.setText("dewolf: nothing to navigate to at cursor");
	}

	private Function resolveFunction(ClangToken token) {
		if (token == null || displayedProgram == null) {
			return null;
		}
		Address address = token.getMinAddress();
		if (address != null) {
			ghidra.program.model.listing.FunctionManager fm =
				displayedProgram.getFunctionManager();
			Function at = fm.getFunctionAt(address);
			if (at != null) {
				return at;
			}
			// The address may be an import-address-table slot (a call through the IAT);
			// Ghidra resolves it to the imported function via a reference.
			Function referenced = fm.getReferencedFunction(address);
			if (referenced != null) {
				return referenced;
			}
		}
		// fall back to the token text (function names may not carry an address)
		String name = token.getText();
		if (name != null && !name.isBlank()) {
			for (Function function : displayedProgram.getFunctionManager().getFunctions(true)) {
				if (name.equals(function.getName())) {
					return function;
				}
			}
		}
		return null;
	}

	/** Esc: cancel any in-flight decompilation and navigate back to the previous function. */
	private void navigateBack() {
		// cancel an in-flight decompilation: bumping the counter makes its result be dropped,
		// so pressing Esc while dewolf is still working returns you to the old function at once
		// (the previous function is restored instantly from the render cache when available).
		requestCounter.incrementAndGet();
		if (history.isEmpty()) {
			statusLabel.setText("dewolf: no further history");
			return;
		}
		HistoryEntry entry = history.pop();
		Program program = entry.program();
		if (program == null || program.isClosed()) {
			program = displayedProgram;
		}
		if (program == null) {
			return;
		}
		Function function = program.getFunctionManager().getFunctionAt(entry.entry());
		if (function == null) {
			statusLabel.setText("dewolf: history target no longer exists");
			return;
		}
		suppressHistory = true;
		try {
			GoToService goToService = tool.getService(GoToService.class);
			if (goToService != null) {
				goToService.goTo(new ProgramLocation(program, function.getEntryPoint()), program);
			}
			showFunction(program, function, false);
		}
		finally {
			suppressHistory = false;
		}
	}

	private void createActions() {
		ToggleDockingAction followAction = new ToggleDockingAction("Follow Cursor", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				followCursor = isSelected();
				if (followCursor) {
					plugin.update();
				}
			}
		};
		followAction.setToolBarData(new ToolBarData(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON));
		followAction.setSelected(true);
		followAction.setDescription("Automatically decompile the function at the cursor location");
		addLocalAction(followAction);

		DockingAction refreshAction = new DockingAction("Refresh", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.forceRefresh();
			}
		};
		refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON));
		refreshAction.setDescription("Re-decompile the current function with dewolf");
		addLocalAction(refreshAction);

		DockingAction renameAction = new DockingAction("Rename Variable", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				renameVariableAtCursor();
			}
		};
		renameAction.setPopupMenuData(new MenuData(new String[] { "Rename Variable" }));
		renameAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, 0));
		renameAction.setDescription("Rename the variable under the cursor (writes to the program database)");
		addLocalAction(renameAction);

		DockingAction retypeAction = new DockingAction("Change Variable Type", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				retypeVariableAtCursor();
			}
		};
		retypeAction.setPopupMenuData(new MenuData(new String[] { "Change Variable Type" }));
		retypeAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_T, KeyEvent.CTRL_DOWN_MASK));
		retypeAction.setDescription("Change the data type of the variable under the cursor");
		addLocalAction(retypeAction);

		DockingAction renameFunctionAction =
			new DockingAction("Rename Function", getOwner()) {
				@Override
				public void actionPerformed(ActionContext context) {
					renameFunctionAtCursor();
				}
			};
		renameFunctionAction
			.setPopupMenuData(new MenuData(new String[] { "Rename Function" }));
		renameFunctionAction
			.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F, KeyEvent.CTRL_DOWN_MASK));
		renameFunctionAction.setDescription(
			"Rename the function under the cursor (its signature or a callee)");
		addLocalAction(renameFunctionAction);

		DockingAction renameDataAction = new DockingAction("Rename Data", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				renameDataAtCursor();
			}
		};
		renameDataAction.setPopupMenuData(new MenuData(new String[] { "Rename Data" }));
		renameDataAction.setDescription("Rename the data/global reference under the cursor");
		addLocalAction(renameDataAction);

		DockingAction backAction = new DockingAction("Back", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				navigateBack();
			}
		};
		backAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_ESCAPE, 0));
		backAction.setDescription("Navigate back to the previously shown function (Esc)");
		addLocalAction(backAction);
	}

	private void renameFunctionAtCursor() {
		if (controller == null || displayedProgram == null) {
			statusLabel.setText("dewolf: nothing to rename here");
			return;
		}
		ClangToken token = controller.getDecompilerPanel().getTokenAtCursor();
		Address address = token == null ? null : token.getMinAddress();
		Function function = address == null ? null
			: displayedProgram.getFunctionManager().getFunctionAt(address);
		if (function == null) {
			statusLabel.setText("dewolf: place the cursor on a function name to rename it");
			return;
		}
		InputDialog dialog = new InputDialog("Rename Function",
			"New name for function '" + function.getName() + "':", function.getName());
		tool.showDialog(dialog);
		if (dialog.isCanceled()) {
			return;
		}
		String oldName = function.getName();
		String newName = dialog.getValue().trim();
		if (newName.isEmpty() || newName.equals(oldName)) {
			return;
		}
		commitAndRefreshInPlace("dewolf: rename function", oldName, newName,
			() -> function.setName(newName, SourceType.USER_DEFINED));
	}

	private void renameDataAtCursor() {
		if (controller == null || displayedProgram == null) {
			statusLabel.setText("dewolf: nothing to rename here");
			return;
		}
		ClangToken token = controller.getDecompilerPanel().getTokenAtCursor();
		Address address = token == null ? null : token.getMinAddress();
		// only treat it as data if it is not a function (functions have their own action)
		if (address == null || displayedProgram.getFunctionManager().getFunctionAt(address) != null) {
			statusLabel.setText("dewolf: place the cursor on a data reference to rename it");
			return;
		}
		ghidra.program.model.symbol.SymbolTable symbolTable = displayedProgram.getSymbolTable();
		ghidra.program.model.symbol.Symbol existing = symbolTable.getPrimarySymbol(address);
		String currentName = existing != null ? existing.getName() : token.getText();
		InputDialog dialog = new InputDialog("Rename Data",
			"New name for data at " + address + ":", currentName);
		tool.showDialog(dialog);
		if (dialog.isCanceled()) {
			return;
		}
		String newName = dialog.getValue().trim();
		if (newName.isEmpty() || newName.equals(currentName)) {
			return;
		}
		ghidra.program.model.symbol.Symbol existingSymbol = existing;
		commitAndRefreshInPlace("dewolf: rename data", token.getText(), newName, () -> {
			if (existingSymbol != null) {
				existingSymbol.setName(newName, SourceType.USER_DEFINED);
			}
			else {
				symbolTable.createLabel(address, newName, SourceType.USER_DEFINED);
			}
		});
	}

	private void renameVariableAtCursor() {
		if (controller == null || currentDecompilation == null || displayedProgram == null) {
			notifyUser("Rename Variable", "There is nothing to rename yet.");
			return;
		}
		ClangToken token = controller.getDecompilerPanel().getTokenAtCursor();
		if (token == null || !token.isVariableRef()) {
			notifyUser("Rename Variable", "Place the cursor on a variable to rename it.");
			return;
		}
		String displayedName = token.getText();
		HighFunction highFunction = currentDecompilation.highFunction;
		if (highFunction == null) {
			notifyUser("Rename Variable", "No decompiler model is available for renaming.");
			return;
		}
		HighSymbol symbol = resolveSymbol(highFunction, displayedName);
		InputDialog dialog =
			new InputDialog("Rename Variable", "New name for '" + displayedName + "':",
				displayedName);
		tool.showDialog(dialog);
		if (dialog.isCanceled()) {
			return;
		}
		String newName = dialog.getValue().trim();
		if (newName.isEmpty() || newName.equals(displayedName)) {
			return;
		}
		if (symbol == null) {
			// An SSA temporary with no backing database variable (Ghidra shows and persists nothing
			// for it either). Rename it in the dewolf view only, so every variable is renameable.
			renameInViewOnly(displayedName, newName);
			return;
		}
		commitAndRefreshInPlace("dewolf: rename variable", displayedName, newName, () -> {
			commitParamsIfNeeded(highFunction, symbol);
			HighFunctionDBUtil.updateDBVariable(symbol, newName, null, SourceType.USER_DEFINED);
		});
	}

	/**
	 * Rename an identifier that has no backing database variable (a lifted SSA temporary) in the
	 * dewolf output ONLY. Recorded per function and re-applied on every re-decompile so it persists
	 * for the session; nothing is written to the program, because there is no variable to write to.
	 */
	private void renameInViewOnly(String oldName, String newName) {
		if (currentDecompilation == null || displayedProgram == null || displayedFunction == null) {
			return;
		}
		viewRenames
			.computeIfAbsent(new HistoryEntry(displayedProgram, displayedFunction.getEntryPoint()),
				k -> new java.util.LinkedHashMap<>())
			.put(oldName, newName);
		suppressNextRefresh = false; // no DB change to swallow
		showDecompilation(displayedProgram, displayedFunction,
			currentDecompilation.withRenamedIdentifier(oldName, newName));
		statusLabel.setText("dewolf: renamed '" + oldName + "' to '" + newName
			+ "' (dewolf view only — no matching database variable)");
	}

	/**
	 * Mirror the built-in RenameVariableTask: when renaming/retyping a parameter (or when the
	 * decompiler's parameters aren't yet committed to the database), the prototype must be
	 * committed first, otherwise updateDBVariable does not persist. This is exactly what makes
	 * the change stick and show up in Ghidra's own decompiler.
	 */
	private static void commitParamsIfNeeded(HighFunction highFunction, HighSymbol symbol)
			throws Exception {
		if (symbol != null && symbol.isParameter()) {
			HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
				HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT, SourceType.USER_DEFINED);
		}
	}

	/**
	 * Surface a blocking condition both as a popup (so the user sees it — a status-bar line is easy
	 * to miss) and in the status label.
	 */
	private void notifyUser(String title, String message) {
		statusLabel.setText("dewolf: " + message);
		Msg.showInfo(this, panel, "dewolf: " + title, message);
	}

	/** Change Variable Type: retype the variable under the cursor via Ghidra's type chooser. */
	private void retypeVariableAtCursor() {
		if (controller == null || currentDecompilation == null || displayedProgram == null) {
			notifyUser("Change Variable Type", "There is nothing to retype yet.");
			return;
		}
		ClangToken token = controller.getDecompilerPanel().getTokenAtCursor();
		if (token == null || !token.isVariableRef()) {
			notifyUser("Change Variable Type", "Place the cursor on a variable to change its type.");
			return;
		}
		HighFunction highFunction = currentDecompilation.highFunction;
		if (highFunction == null) {
			notifyUser("Change Variable Type", "No decompiler model is available for retyping.");
			return;
		}
		HighSymbol symbol = resolveSymbol(highFunction, token.getText());
		if (symbol == null) {
			// Unlike rename, a retype cannot be a view-only edit: with no backing database variable
			// there is nothing to type, and dewolf re-derives types from the pipeline each run.
			notifyUser("Cannot Change Variable Type", "'" + token.getText()
				+ "' has no backing database variable — it is a lifted SSA temporary, so its type "
				+ "cannot be changed. (Renaming it still works, in the dewolf view.)");
			return;
		}
		DataType chosen = chooseDataType(symbol.getDataType());
		if (chosen == null) {
			return; // cancelled
		}
		// a retype changes the declaration, so re-decompile fully (types propagate through
		// the pipeline); still cheaper to route through forceRefresh than to guess the delta
		int transaction = displayedProgram.startTransaction("dewolf: change variable type");
		boolean success = false;
		try {
			commitParamsIfNeeded(highFunction, symbol);
			HighFunctionDBUtil.updateDBVariable(symbol, null, chosen, SourceType.USER_DEFINED);
			success = true;
		}
		catch (Exception e) {
			Msg.showError(this, panel, "dewolf: Retype Failed", e.getMessage(), e);
		}
		finally {
			displayedProgram.endTransaction(transaction, success);
		}
		statusLabel.setText("dewolf: changed type of " + token.getText() + " to " + chosen.getName());
		// A retype changes types that propagate through the whole pipeline, so re-decompile. The
		// passive program-change listener is debounced (up to ~1.5s) and would only take effect on
		// the next event, so trigger the refresh explicitly here for an immediate update.
		plugin.forceRefresh();
	}

	private DataType chooseDataType(DataType current) {
		DataTypeManager dtm = displayedProgram.getDataTypeManager();
		DataTypeSelectionDialog dialog =
			new DataTypeSelectionDialog(tool, dtm, Integer.MAX_VALUE, AllowedDataTypes.FIXED_LENGTH);
		dialog.setInitialDataType(current);
		tool.showDialog(dialog);
		return dialog.getUserChosenDataType();
	}

	/**
	 * Commit a name change to the database, then refresh the view IN PLACE by patching the
	 * already-rendered decompilation instead of re-running dewolf's pipeline. A rename only
	 * changes a variable's displayed text, so this is instant and avoids a full re-decompile.
	 */
	private void commitAndRefreshInPlace(String txName, String oldName, String newName,
			Commit commit) {
		int transaction = displayedProgram.startTransaction(txName);
		boolean success = false;
		try {
			commit.run();
			success = true;
		}
		catch (Exception e) {
			Msg.showError(this, panel, "dewolf: Rename Failed", e.getMessage(), e);
		}
		finally {
			displayedProgram.endTransaction(transaction, success);
		}
		if (!success || currentDecompilation == null) {
			return;
		}
		// swallow the auto-refresh the commit triggers, then patch the view directly
		suppressNextRefresh = true;
		DewolfDecompilation patched = currentDecompilation.withRenamedIdentifier(oldName, newName);
		showDecompilation(displayedProgram, displayedFunction, patched);
		statusLabel.setText("dewolf: renamed to " + newName);
	}

	/**
	 * Resolve the HighSymbol for an identifier shown in the dewolf output.
	 *
	 * dewolf very often displays a variable under a name that already matches Ghidra's own
	 * (parameters like {@code param_2}, stack locals like {@code local_10}, user-named
	 * variables), so try the displayed name against the database DIRECTLY first. Only if that
	 * misses do we fall back to the dewolf->Ghidra provenance map (which recovers cases where
	 * out-of-SSA renamed a local to {@code var_N}). Consulting provenance first was actively
	 * harmful: it rewrote a directly-matchable {@code param_2} to an internal lift-name
	 * ({@code u927}) that matches no database symbol — which is exactly why parameters could
	 * not be renamed.
	 */
	private HighSymbol resolveSymbol(HighFunction highFunction, String displayedName) {
		HighSymbol direct = findLocalSymbol(highFunction, displayedName);
		if (direct != null) {
			return direct;
		}
		String origin = currentDecompilation.originalNames.getOrDefault(displayedName, displayedName);
		return origin.equals(displayedName) ? null : findLocalSymbol(highFunction, origin);
	}

	private static HighSymbol findLocalSymbol(HighFunction highFunction, String name) {
		Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
		while (symbols.hasNext()) {
			HighSymbol symbol = symbols.next();
			if (name.equals(symbol.getName())) {
				return symbol;
			}
		}
		return null;
	}

	void locationUpdated(Program program, ProgramLocation location, boolean force) {
		// An in-place rename/retype just patched the view and bumped the modification
		// number; swallow the single resulting refresh so we don't also re-decompile.
		if (suppressNextRefresh && !force) {
			suppressNextRefresh = false;
			return;
		}
		// Decompile regardless of whether the dewolf tab is the active one: the built-in
		// decompiler updates in the background too, so switching to the window later shows
		// the right function. (isVisible() would short-circuit whenever this window is in
		// a background tab, which is exactly when cursor-follow must still work.)
		if (program == null || location == null || location.getAddress() == null) {
			return;
		}
		if (!followCursor && !force) {
			return;
		}
		Address address = location.getAddress();
		if (address.isExternalAddress()) {
			return; // nothing to decompile for external/thunk targets, like the built-in
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			return; // keep showing the last decompiled function (cursor is on data/etc.)
		}
		long modNumber = program.getModificationNumber();
		boolean sameFunction = program == displayedProgram &&
			function.getEntryPoint().equals(displayedEntry);
		if (sameFunction && modNumber == displayedModNumber && !force) {
			return; // nothing changed (the cursor just moved within the same function)
		}
		if (sameFunction) {
			// Same function, but the database changed (retype/rename) or a refresh was forced:
			// re-decompile in place. showFunction would early-return on the unchanged entry, so a
			// same-function refresh has to go through here. (A rename that patched the view in
			// place set suppressNextRefresh and already returned above.)
			displayedModNumber = modNumber;
			decompile(program, function, true); // keep the existing output up while re-decompiling
			return;
		}
		showFunction(program, function, true);
	}

	/**
	 * Switch the window to a function and decompile it. When {@code recordHistory} is true and
	 * the function differs from the one shown, the previous function is pushed onto the back
	 * history (Esc).
	 */
	private void showFunction(Program program, Function function, boolean recordHistory) {
		if (function == null || function.getEntryPoint().equals(displayedEntry) &&
			program == displayedProgram) {
			return; // same function, nothing to switch to
		}
		if (recordHistory && !suppressHistory && displayedFunction != null &&
			displayedProgram != null) {
			history.push(new HistoryEntry(displayedProgram, displayedEntry));
			while (history.size() > HISTORY_LIMIT) {
				history.removeLast();
			}
		}
		displayedProgram = program;
		displayedFunction = function;
		displayedEntry = function.getEntryPoint();
		displayedModNumber = program.getModificationNumber();
		// instant restore if we already rendered this exact function+db-version
		HistoryEntry key = new HistoryEntry(program, function.getEntryPoint());
		Rendered cached = rendered.get(key);
		if (cached != null && cached.modificationNumber == displayedModNumber) {
			requestCounter.incrementAndGet(); // drop any in-flight decompilation
			showDecompilation(program, function, cached.decompilation);
			statusLabel.setText("dewolf: " + function.getName());
			schedulePrefetch(program, function);
			return;
		}
		decompile(program, function);
	}

	private void decompile(Program program, Function function) {
		decompile(program, function, false);
	}

	/**
	 * Decompile {@code function} on the background worker.
	 *
	 * @param keepCurrentView when true (a same-function refresh, e.g. after a retype), the currently
	 *     rendered output is left on screen while the new decompilation runs, so the view does not
	 *     flash back to "decompiling ..." — the fresh result simply replaces it when ready. When false
	 *     (switching to a different, not-yet-rendered function) the placeholder is shown immediately so
	 *     the user does not stare at the stale previous function.
	 */
	private void decompile(Program program, Function function, boolean keepCurrentView) {
		DewolfBackend backend = DewolfBackendRegistry.getBackend();
		if (backend == null) {
			showMessage(NO_BACKEND_TEXT);
			statusLabel.setText("dewolf: backend not connected");
			return;
		}
		initializeOptions(program);
		long requestId = requestCounter.incrementAndGet();
		// Cancel any in-flight background prefetch so this user-driven decompile can take the
		// worker immediately (the prefetch aborts at its next pipeline-stage checkpoint).
		prefetchGeneration.incrementAndGet();
		String functionName = function.getName();
		if (keepCurrentView && currentDecompilation != null) {
			// Refreshing a function that is already displayed: keep its output visible (it is only
			// slightly stale) and just signal work in the status line, rather than blanking the view.
			statusLabel.setText("dewolf: refreshing " + functionName + " ...");
		}
		else {
			// dewolf can be slow; clear the view to an explicit "decompiling" message right away
			// so the user sees the window is working on the new function, not the stale one.
			currentDecompilation = null;
			showMessage("// dewolf: decompiling " + functionName + " ...");
			statusLabel.setText("dewolf: decompiling " + functionName + " ...");
		}
		setSubTitle(functionName);
		executor.execute(new PrioritizedTask(0, taskSequence.incrementAndGet(), () -> {
			DewolfDecompilation decompilation = null;
			String error = null;
			try {
				// cancel this decompile the moment a newer navigation supersedes it
				decompilation = backend.decompile(program, function,
					() -> requestId != requestCounter.get());
			}
			catch (Throwable t) {
				error = "// dewolf failed to decompile " + functionName + ":\n// " + t;
			}
			DewolfDecompilation result = decompilation;
			String errorText = error;
			SwingUtilities.invokeLater(() -> {
				if (requestId != requestCounter.get()) {
					return; // a newer request (or Esc) superseded this one
				}
				if (result == null) {
					// null with no error text means the decompile was cancelled by a newer
					// navigation; the requestId guard above normally already returned in that case
					if (errorText != null) {
						showMessage(errorText);
						statusLabel.setText("dewolf: " + functionName);
					}
					return;
				}
				showDecompilation(program, function, result);
				schedulePrefetch(program, function);
				statusLabel.setText("dewolf: " + functionName);
			});
		}));
	}

	/**
	 * Seed background prefetch from the just-displayed function: decompile its callees
	 * breadth-first, then any other not-yet-cached function, so navigating to them is instant.
	 * Best-effort and low priority; superseded whenever another function is displayed or the
	 * database changes. Runs on the Swing thread.
	 */
	private void schedulePrefetch(Program program, Function function) {
		if (program == null || function == null || DewolfBackendRegistry.getBackend() == null) {
			return;
		}
		long modNumber = program.getModificationNumber();
		if (modNumber != prefetchDoneModNumber) {
			prefetchDone.clear(); // the database changed: every cached decompilation is stale
			prefetchDoneModNumber = modNumber;
		}
		long generation = prefetchGeneration.incrementAndGet();
		prefetchQueue.clear();
		prefetchEnqueued.clear();
		prefetchCount = 0;
		prefetchEnqueued.add(function.getEntryPoint());
		prefetchDone.add(function.getEntryPoint()); // the displayed function is already rendered
		enqueueNeighbors(program, function);
		pumpPrefetch(program, generation);
	}

	/**
	 * Add a function's call-graph neighbours — its callees AND its callers — to the breadth-first
	 * prefetch frontier. Expanding in both directions makes prefetch fan out by call-graph distance
	 * from the displayed function, so the functions you are most likely to navigate to next (down
	 * into a callee, or back up to a caller you came from) are decompiled first. Callees are added
	 * before callers, giving a slight bias to descending the call tree. (Swing thread.)
	 */
	private void enqueueNeighbors(Program program, Function function) {
		java.util.Set<Function> neighbors = new java.util.LinkedHashSet<>();
		try {
			neighbors.addAll(function.getCalledFunctions(ghidra.util.task.TaskMonitor.DUMMY));
		}
		catch (Throwable t) {
			// call-graph queries are best-effort; a failure just means less prefetching
		}
		try {
			neighbors.addAll(function.getCallingFunctions(ghidra.util.task.TaskMonitor.DUMMY));
		}
		catch (Throwable t) {
			// ditto for the callers
		}
		for (Function neighbor : neighbors) {
			if (neighbor == null || neighbor.isExternal() || neighbor.isThunk()) {
				continue;
			}
			Address entry = neighbor.getEntryPoint();
			if (prefetchEnqueued.add(entry)) {
				prefetchQueue.add(entry);
			}
		}
	}

	/**
	 * Pick the next function to prefetch (breadth-first callees first, then any remaining function)
	 * and submit ONE low-priority decompile for it, skipping functions already cached at this
	 * database version. Chained: each finished prefetch calls back here. Runs on the Swing thread.
	 */
	private void pumpPrefetch(Program program, long generation) {
		if (generation != prefetchGeneration.get() || program.isClosed()) {
			return; // superseded by a newer display, or the program was closed
		}
		if (program != displayedProgram || program.getModificationNumber() != prefetchDoneModNumber) {
			return; // the user moved to another program or edited the database; the seed is stale
		}
		while (prefetchCount < PREFETCH_LIMIT) {
			Address entry = prefetchQueue.poll();
			if (entry == null) {
				entry = nextUncachedFunction(program);
			}
			if (entry == null) {
				return; // everything reachable is cached
			}
			Function function = program.getFunctionManager().getFunctionAt(entry);
			if (function == null) {
				continue;
			}
			Rendered cached = rendered.get(new HistoryEntry(program, entry));
			if (cached != null && cached.modificationNumber == prefetchDoneModNumber) {
				// already rendered at this database version: expand the frontier and keep looking
				prefetchDone.add(entry);
				enqueueNeighbors(program, function);
				continue;
			}
			submitPrefetch(program, function, generation);
			return; // one decompile in flight; it will pump the next on completion
		}
	}

	/** The entry of some function not yet prefetched at this database version, or null. */
	private Address nextUncachedFunction(Program program) {
		for (Function function : program.getFunctionManager().getFunctions(true)) {
			if (function.isExternal() || function.isThunk()) {
				continue;
			}
			Address entry = function.getEntryPoint();
			if (prefetchDone.contains(entry) || !prefetchEnqueued.add(entry)) {
				continue;
			}
			return entry;
		}
		return null;
	}

	/** Submit one low-priority (prefetch) decompile; on completion cache it and pump the next. */
	private void submitPrefetch(Program program, Function function, long generation) {
		DewolfBackend backend = DewolfBackendRegistry.getBackend();
		if (backend == null) {
			return;
		}
		prefetchCount++;
		long modNumber = program.getModificationNumber();
		executor.execute(new PrioritizedTask(1, taskSequence.incrementAndGet(), () -> {
			DewolfDecompilation result = null;
			try {
				// abandon this prefetch the moment a newer seed (usually a user navigation) arrives
				result = backend.decompile(program, function,
					() -> generation != prefetchGeneration.get());
			}
			catch (Throwable t) {
				// prefetch failures are silent: the function just won't be pre-cached
			}
			DewolfDecompilation prefetched = result;
			SwingUtilities.invokeLater(
				() -> onPrefetched(program, function, generation, modNumber, prefetched));
		}));
	}

	/** A prefetch decompile finished: cache it for instant navigation, then pump the next. */
	private void onPrefetched(Program program, Function function, long generation, long modNumber,
			DewolfDecompilation result) {
		if (generation != prefetchGeneration.get()) {
			return; // a newer seed superseded this prefetch
		}
		Address entry = function.getEntryPoint();
		prefetchDone.add(entry);
		if (result != null && !program.isClosed() &&
			program.getModificationNumber() == modNumber) {
			HistoryEntry key = new HistoryEntry(program, entry);
			Rendered existing = rendered.get(key);
			// don't clobber a fresher foreground render for the same key
			if (existing == null || existing.modificationNumber != modNumber) {
				rendered.put(key, new Rendered(result, modNumber));
			}
			enqueueNeighbors(program, function);
		}
		pumpPrefetch(program, generation);
	}

	private void showDecompilation(Program program, Function function,
			DewolfDecompilation decompilation) {
		HistoryEntry key = new HistoryEntry(program, function.getEntryPoint());
		// Re-apply any view-only renames (of variables with no backing database symbol) so they
		// survive re-decompiles for the session. Applied in insertion order so chained renames hold.
		java.util.LinkedHashMap<String, String> views = viewRenames.get(key);
		if (views != null) {
			for (java.util.Map.Entry<String, String> entry : views.entrySet()) {
				decompilation = decompilation.withRenamedIdentifier(entry.getKey(), entry.getValue());
			}
		}
		currentDecompilation = decompilation;
		rendered.put(key, new Rendered(decompilation, program.getModificationNumber()));
		// Keep the window title in sync with whatever is actually on screen. Every display path funnels
		// through here -- fresh decompile, instant cache-restore (Esc back / revisited callee), and
		// in-place rename refresh -- whereas decompile()'s placeholder setSubTitle only fires on the slow
		// background path, so cache-restores used to leave the previous function's name in the title.
		setSubTitle(function.getName());
		if (controller == null) {
			setFallbackCode(decompilation.code);
			return;
		}
		try {
			controller.setDecompileData(DewolfMarkupBuilder.build(program, function, decompilation));
		}
		catch (Throwable t) {
			switchToFallback(t);
			setFallbackCode(decompilation.code);
		}
	}

	private void showMessage(String message) {
		if (controller == null) {
			setFallbackCode(message);
			return;
		}
		try {
			controller.setDecompileData(new EmptyDecompileData(message));
		}
		catch (Throwable t) {
			switchToFallback(t);
			setFallbackCode(message);
		}
	}

	private void setFallbackCode(String text) {
		codeArea.setText(text);
		CSyntaxHighlighter.highlight(codeArea.getStyledDocument(), text);
		codeArea.setCaretPosition(0);
	}

	private void switchToFallback(Throwable cause) {
		Msg.error(this, "dewolf: DecompilerPanel rendering failed, switching to plain text view",
			cause);
		DecompilerController failedController = controller;
		controller = null;
		try {
			panel.remove(failedController.getDecompilerPanel());
			failedController.dispose();
		}
		catch (Throwable t) {
			Msg.warn(this, "dewolf: cleaning up the failed DecompilerPanel failed", t);
		}
		panel.add(fallbackComponent, BorderLayout.CENTER);
		panel.revalidate();
		panel.repaint();
	}

	/** Mirror CDisplay.initializeOptions: adopt the tool's decompiler options (fonts, colors). */
	private void initializeOptions(Program program) {
		if (controller == null || program == optionsProgram) {
			return;
		}
		optionsProgram = program;
		ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		ToolOptions options = tool.getOptions("Decompiler");
		decompileOptions.grabFromToolAndProgram(fieldOptions, options, program);
		// dewolf's output is already formatted (astyle) into final lines; stop the panel
		// from re-wrapping them at the decompiler's default ~100-char width.
		decompileOptions.setMaxWidth(100000);
		controller.setOptions(decompileOptions);
	}

	void programClosed(Program program) {
		history.removeIf(entry -> entry.program() == program);
		rendered.keySet().removeIf(entry -> entry.program() == program);
		viewRenames.keySet().removeIf(entry -> entry.program() == program);
		// supersede any in-flight/queued prefetch and drop its bookkeeping
		prefetchGeneration.incrementAndGet();
		prefetchQueue.clear();
		prefetchEnqueued.clear();
		prefetchDone.clear();
		prefetchDoneModNumber = -1;
		if (program == displayedProgram) {
			displayedProgram = null;
			displayedFunction = null;
			displayedEntry = null;
			displayedModNumber = -1;
			currentDecompilation = null;
			requestCounter.incrementAndGet(); // drop in-flight results for this program
			showMessage(WELCOME_TEXT);
			setSubTitle(null);
			statusLabel.setText(" ");
		}
		if (program == optionsProgram) {
			optionsProgram = null;
		}
		if (controller != null) {
			controller.programClosed(program);
		}
	}

	@Override
	public void componentShown() {
		plugin.update();
	}

	void dispose() {
		executor.shutdownNow();
		if (controller != null) {
			controller.dispose();
		}
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
