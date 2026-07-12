package dewolfghidra;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Bridge interface implemented on the Python side (via JPype) by the dewolf decompiler.
 * Implementations may be called from any background thread, but never concurrently.
 */
public interface DewolfBackend {

	/**
	 * Give the backend the plugin's tool so it can register dewolf's options in the tool's
	 * options (Edit -> Tool Options -> dewolf) and read them back at decompile time.
	 * Called once on the Swing thread when the plugin is created.
	 */
	void initialize(PluginTool tool);

	/**
	 * Decompile the given function. On failure the result's code/tokens contain an
	 * error report as C comments (implementations should not throw, but callers must
	 * still guard against it).
	 *
	 * <p>{@code cancel} is polled between pipeline stages; if it reports cancellation the
	 * decompilation is abandoned and {@code null} is returned (the caller discards superseded
	 * results anyway). Pass a signal that never cancels to run to completion.
	 */
	DewolfDecompilation decompile(Program program, Function function, DewolfCancellation cancel);

	/**
	 * Notification that a program was closed so per-program resources can be released.
	 */
	void programClosed(Program program);
}
