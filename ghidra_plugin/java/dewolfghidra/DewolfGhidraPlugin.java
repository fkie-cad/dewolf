package dewolfghidra;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.SwingUpdateManager;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = "dewolf",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "dewolf decompiler view",
	description = "Shows the output of the dewolf decompiler for the function at the "
		+ "current cursor location in a dockable window. Requires Ghidra to be launched "
		+ "through dewolf's PyGhidra launcher (python -m ghidra_plugin)."
)
//@formatter:on
public class DewolfGhidraPlugin extends ProgramPlugin {

	private final DewolfProvider provider;
	// Debounce cursor movement like the built-in DecompilePlugin does, so scrolling
	// through the listing does not queue a decompilation per event.
	private final SwingUpdateManager updateManager = new SwingUpdateManager(500, 1500, this::update);
	// Coarse refresh on any program change (rename, retype, ...), like the built-in
	// decompiler's DecompilerProgramListener; the provider's modification-number check
	// turns no-op events into cache hits.
	private final DomainObjectListener programListener = event -> updateManager.update();

	public DewolfGhidraPlugin(PluginTool tool) {
		super(tool);
		provider = new DewolfProvider(this);
		DewolfBackend backend = DewolfBackendRegistry.getBackend();
		if (backend != null) {
			try {
				backend.initialize(tool);
			}
			catch (Throwable t) {
				// options registration must never prevent the plugin from loading
			}
		}
		// re-decompile the current function when the user changes a dewolf option
		// (Edit -> Tool Options -> dewolf); force past the same-function/render caches
		tool.getOptions("dewolf").addOptionsChangeListener(
			(options, optionName, oldValue, newValue) -> forceRefresh());
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(programListener);
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(programListener);
	}

	@Override
	protected void locationChanged(ProgramLocation location) {
		if (location == null) {
			return;
		}
		updateManager.update();
	}

	@Override
	protected void programClosed(Program program) {
		provider.programClosed(program);
		DewolfBackend backend = DewolfBackendRegistry.getBackend();
		if (backend != null) {
			try {
				backend.programClosed(program);
			}
			catch (Throwable t) {
				// backend cleanup must never break program closing
			}
		}
	}

	void update() {
		provider.locationUpdated(currentProgram, currentLocation, false);
	}

	void forceRefresh() {
		provider.locationUpdated(currentProgram, currentLocation, true);
	}

	@Override
	protected void dispose() {
		updateManager.dispose();
		provider.dispose();
		super.dispose();
	}
}
