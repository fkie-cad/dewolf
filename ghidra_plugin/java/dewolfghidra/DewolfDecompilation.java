package dewolfghidra;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.pcode.HighFunction;

/**
 * Result of one dewolf decompilation, handed from the Python backend to the plugin.
 * {@code code} is the plain formatted C text (fallback rendering); {@code tokens} is
 * the same content as a classified token stream for the DecompilerPanel renderer;
 * {@code highFunction} is Ghidra's decompiler model of the function (may be null);
 * {@code originalNames} maps a displayed variable name to the name of the Ghidra
 * HighSymbol it originates from (dewolf merges/renames variables, so displayed names
 * usually differ from the database names a rename must target).
 */
public final class DewolfDecompilation {

	public final String code;
	public final DewolfTokenData[] tokens;
	public final HighFunction highFunction;
	public final Map<String, String> originalNames;

	public DewolfDecompilation(String code, DewolfTokenData[] tokens, HighFunction highFunction,
			Map<String, String> originalNames) {
		this.code = code;
		this.tokens = tokens;
		this.highFunction = highFunction;
		this.originalNames = originalNames;
	}

	/**
	 * A copy of this decompilation with every identifier token reading {@code oldName}
	 * renamed to {@code newName}, and the provenance/original-name map updated to match.
	 * Used to refresh the view after a rename without re-running dewolf's pipeline: a
	 * rename only changes a variable's displayed text, not the structure of the output.
	 */
	public DewolfDecompilation withRenamedIdentifier(String oldName, String newName) {
		DewolfTokenData[] newTokens = new DewolfTokenData[tokens.length];
		for (int i = 0; i < tokens.length; i++) {
			DewolfTokenData token = tokens[i];
			if (token.kind != DewolfTokenData.BREAK && oldName.equals(token.text)) {
				newTokens[i] = new DewolfTokenData(token.kind, newName, token.address, token.indent);
			}
			else {
				newTokens[i] = token;
			}
		}
		String newCode = renameWholeWord(code, oldName, newName);
		Map<String, String> newOriginals = new HashMap<>(originalNames);
		String origin = newOriginals.remove(oldName);
		// after the rename the displayed name IS the database name, so it maps to itself
		newOriginals.put(newName, origin != null ? newName : newName);
		return new DewolfDecompilation(newCode, newTokens, highFunction, newOriginals);
	}

	private static String renameWholeWord(String text, String oldName, String newName) {
		StringBuilder result = new StringBuilder(text.length());
		int i = 0;
		int n = text.length();
		int len = oldName.length();
		while (i < n) {
			if (i + len <= n && text.regionMatches(i, oldName, 0, len) &&
				!isIdentifierChar(charBefore(text, i)) && !isIdentifierChar(charAt(text, i + len))) {
				result.append(newName);
				i += len;
			}
			else {
				result.append(text.charAt(i));
				i++;
			}
		}
		return result.toString();
	}

	private static char charBefore(String s, int i) {
		return i > 0 ? s.charAt(i - 1) : ' ';
	}

	private static char charAt(String s, int i) {
		return i < s.length() ? s.charAt(i) : ' ';
	}

	private static boolean isIdentifierChar(char c) {
		return Character.isLetterOrDigit(c) || c == '_';
	}
}
