package dewolfghidra;

import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompileProcess;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;

/**
 * DecompileResults not produced by the native decompiler process: carries a
 * synthesized token tree (dewolf output) and an optional HighFunction. The super
 * constructor tolerates a null decoder (decodeStream returns immediately), so no
 * native state is involved.
 */
class DewolfDecompileResults extends DecompileResults {

	private final ClangTokenGroup markup;
	private final HighFunction highFunction;

	DewolfDecompileResults(Function function, HighFunction highFunction,
			ClangTokenGroup markup) {
		super(function, function.getProgram().getLanguage(),
			function.getProgram().getCompilerSpec(), null, null, null,
			DecompileProcess.DisposeState.NOT_DISPOSED);
		this.markup = markup;
		this.highFunction = highFunction;
	}

	@Override
	public boolean decompileCompleted() {
		return true;
	}

	@Override
	public boolean isValid() {
		return true;
	}

	@Override
	public String getErrorMessage() {
		return null;
	}

	@Override
	public ClangTokenGroup getCCodeMarkup() {
		return markup;
	}

	@Override
	public HighFunction getHighFunction() {
		return highFunction;
	}
}
