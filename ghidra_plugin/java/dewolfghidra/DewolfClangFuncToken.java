package dewolfghidra;

import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A function-name token that Ghidra's decompiler panel colors like a real one.
 *
 * ClangLayoutController colors function names only through ClangFuncNameToken (via
 * DecompilerUtils.getFunction, which for a CALL reads the token's PcodeOp input(0)
 * address and resolves the referenced function). We therefore carry a synthetic CALL
 * PcodeOp whose input addresses the callee, so the panel resolves the function and gives
 * it the normal internal-function color (or red for externals) — instead of falling
 * through to the error color (red) as a plain token would.
 *
 * The public ClangFuncNameToken constructor leaves the text null and its op private with
 * no setter, so text and getPcodeOp are overridden here.
 */
class DewolfClangFuncToken extends ClangFuncNameToken {

	private final String text;
	private final PcodeOp op;
	private final Address address;

	DewolfClangFuncToken(ClangNode parent, String text, PcodeOp op, Address address) {
		super(parent, null);
		this.text = text;
		this.op = op;
		this.address = address;
	}

	@Override
	public String getText() {
		return text;
	}

	@Override
	public String toString() {
		return text;
	}

	@Override
	public PcodeOp getPcodeOp() {
		return op;
	}

	@Override
	public Address getMinAddress() {
		return address;
	}

	@Override
	public Address getMaxAddress() {
		return address;
	}
}
