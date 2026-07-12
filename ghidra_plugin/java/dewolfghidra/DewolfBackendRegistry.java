package dewolfghidra;

/**
 * Holds the {@link DewolfBackend} registered by the Python side before the GUI starts.
 * Empty when Ghidra was launched without dewolf (plain ghidraRun): the plugin then
 * shows a hint instead of decompiling.
 */
public final class DewolfBackendRegistry {

	private static volatile DewolfBackend backend;

	private DewolfBackendRegistry() {
	}

	public static void setBackend(DewolfBackend newBackend) {
		backend = newBackend;
	}

	public static DewolfBackend getBackend() {
		return backend;
	}
}
