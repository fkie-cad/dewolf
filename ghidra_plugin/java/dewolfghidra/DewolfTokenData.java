package dewolfghidra;

/**
 * One output token produced by the dewolf backend. {@code kind} is either
 * {@link #BREAK} (line break; {@code indent} is the indent level) or one of the
 * {@code ghidra.app.decompiler.ClangToken} color constants (KEYWORD_COLOR, ...),
 * which double as the token classification. {@code address} is the offset of the
 * associated program location, or -1 if the token has none.
 */
public final class DewolfTokenData {

	public static final int BREAK = -1;

	public final int kind;
	public final String text;
	public final long address;
	public final int indent;

	public DewolfTokenData(int kind, String text, long address, int indent) {
		this.kind = kind;
		this.text = text;
		this.address = address;
		this.indent = indent;
	}
}
