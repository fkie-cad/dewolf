package dewolfghidra;

import ghidra.app.decompiler.ClangBreak;
import ghidra.app.decompiler.ClangNode;

/**
 * ClangBreak with empty (instead of null) text. Decoder-built breaks call
 * setText("") in decode(); the public constructor leaves the text null, which panel
 * code and toString() do not tolerate. setText is package-private, so override the
 * accessors instead.
 */
class DewolfClangBreak extends ClangBreak {

	DewolfClangBreak(ClangNode parent, int indent) {
		super(parent, indent);
	}

	@Override
	public String getText() {
		return "";
	}

	@Override
	public String toString() {
		return "";
	}
}
