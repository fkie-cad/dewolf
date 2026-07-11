package dewolfghidra;

/**
 * Cooperative cancellation signal handed to {@link DewolfBackend#decompile}. The backend polls it
 * between pipeline stages and aborts early (returning {@code null}) once it becomes cancelled, so a
 * user navigation can free the single decompile worker for the function they want next instead of
 * waiting for an in-flight background/foreground decompile to finish (dewolf cannot be killed
 * mid-stage).
 */
@FunctionalInterface
public interface DewolfCancellation {

	/** @return true once the decompilation that received this signal has been superseded. */
	boolean isCancelled();
}
