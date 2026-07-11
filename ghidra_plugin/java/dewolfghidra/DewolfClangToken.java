package dewolfghidra;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.program.model.address.Address;

/**
 * A ClangToken that carries its own program address. The base class returns null from
 * getMinAddress()/getMaxAddress() and only decoder-built subclasses carry addresses;
 * DecompilerUtils.getClosestAddress() consults getMinAddress() first, so overriding
 * here is sufficient for click-to-Listing navigation.
 */
class DewolfClangToken extends ClangToken {

	private final Address address;
	private final boolean variableRef;

	DewolfClangToken(ClangNode parent, String text, int color, Address address,
			boolean variableRef) {
		super(parent, text, color);
		this.address = address;
		this.variableRef = variableRef;
	}

	@Override
	public Address getMinAddress() {
		return address;
	}

	@Override
	public Address getMaxAddress() {
		return address;
	}

	@Override
	public boolean isVariableRef() {
		return variableRef;
	}
}
