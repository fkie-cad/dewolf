package dewolfghidra;

import ghidra.app.decompiler.ClangFunction;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.component.DecompileData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.ProgramLocation;

/**
 * Builds a DecompileData for the DecompilerPanel from a dewolf token stream, mirroring
 * the structure the decoder produces (and ClangLayoutController.addErrorLayout uses):
 * per source line one ClangTokenGroup starting with a ClangBreak carrying the indent.
 */
public final class DewolfMarkupBuilder {

	private DewolfMarkupBuilder() {
	}

	public static DecompileData build(Program program, Function function,
			DewolfDecompilation decompilation) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Address entry = function.getEntryPoint();
		ClangFunction root = new ClangFunction(null, decompilation.highFunction);
		ClangStatement line = newLine(root, 0);
		for (DewolfTokenData token : decompilation.tokens) {
			if (token.kind == DewolfTokenData.BREAK) {
				root.AddTokenGroup(line);
				line = newLine(root, token.indent);
				continue;
			}
			Address address = token.address >= 0 ? space.getAddress(token.address) : null;
			if (token.kind == ClangToken.FUNCTION_COLOR) {
				// emit a real ClangFuncNameToken so the panel colors it like the built-in
				// decompiler (internal function color, or red for externals)
				line.AddTokenGroup(new DewolfClangFuncToken(line, token.text,
					callOpTo(entry, address), address));
				continue;
			}
			boolean variableRef =
				token.kind == ClangToken.VARIABLE_COLOR ||
					token.kind == ClangToken.PARAMETER_COLOR;
			line.AddTokenGroup(new DewolfClangToken(line, token.text, token.kind, address, variableRef));
		}
		root.AddTokenGroup(line);

		DewolfDecompileResults results =
			new DewolfDecompileResults(function, decompilation.highFunction, root);
		ProgramLocation location = new ProgramLocation(program, function.getEntryPoint());
		return new DecompileData(program, function, location, results, null, null, null);
	}

	/**
	 * A synthetic CALL PcodeOp whose input(0) addresses the callee, so
	 * DecompilerUtils.getFunction (used by the panel to color a ClangFuncNameToken) resolves
	 * the referenced function. {@code callee} may be null (e.g. the function's own signature
	 * name) — then no address input is set and the panel simply uses the default color.
	 */
	private static PcodeOp callOpTo(Address here, Address callee) {
		Varnode[] inputs = callee != null
				? new Varnode[] { new Varnode(callee, 1) }
				: new Varnode[0];
		return new PcodeOp(new SequenceNumber(here, 0), PcodeOp.CALL, inputs, null);
	}

	private static ClangStatement newLine(ClangTokenGroup root, int indent) {
		ClangStatement line = new ClangStatement(root);
		line.AddTokenGroup(new DewolfClangBreak(line, indent));
		return line;
	}
}
