package dewolfghidra;

import java.awt.Color;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

import generic.theme.GColor;

/**
 * Minimal regex-based C syntax highlighting for the dewolf code view. Uses the theme
 * color ids of the built-in decompiler so the output matches its look and follows
 * theme (light/dark) changes.
 */
final class CSyntaxHighlighter {

	static final Color FOREGROUND = new GColor("color.fg.decompiler");
	static final Color BACKGROUND = new GColor("color.bg.decompiler");
	private static final Color KEYWORD = new GColor("color.fg.decompiler.keyword");
	private static final Color TYPE = new GColor("color.fg.decompiler.type");
	private static final Color CONSTANT = new GColor("color.fg.decompiler.constant");
	private static final Color COMMENT = new GColor("color.fg.decompiler.comment");

	private static final Pattern KEYWORDS = Pattern.compile(
		"\\b(if|else|while|do|for|switch|case|default|break|continue|return|goto|" +
		"struct|union|enum|typedef|sizeof|extern|static|const|volatile|true|false|NULL)\\b");
	private static final Pattern TYPES = Pattern.compile(
		"\\b(u?int(8|16|32|64|128)_t|size_t|ssize_t|void|bool|char|short|int|long|" +
		"float|double|unsigned|signed)\\b");
	private static final Pattern NUMBERS = Pattern.compile(
		"\\b(0[xX][0-9a-fA-F]+|\\d+(\\.\\d+)?([uUlLfF]*))\\b");
	private static final Pattern STRINGS = Pattern.compile(
		"\"(\\\\.|[^\"\\\\])*\"|'(\\\\.|[^'\\\\])*'");
	private static final Pattern COMMENTS = Pattern.compile(
		"//[^\n]*|/\\*.*?\\*/", Pattern.DOTALL);

	private CSyntaxHighlighter() {
	}

	static void highlight(StyledDocument document, String text) {
		SimpleAttributeSet plain = attributes(FOREGROUND);
		document.setCharacterAttributes(0, text.length(), plain, true);
		// order matters: later passes override earlier ones, comments win
		apply(document, text, NUMBERS, CONSTANT);
		apply(document, text, TYPES, TYPE);
		apply(document, text, KEYWORDS, KEYWORD);
		apply(document, text, STRINGS, CONSTANT);
		apply(document, text, COMMENTS, COMMENT);
	}

	private static void apply(StyledDocument document, String text, Pattern pattern, Color color) {
		SimpleAttributeSet attributes = attributes(color);
		Matcher matcher = pattern.matcher(text);
		while (matcher.find()) {
			document.setCharacterAttributes(matcher.start(), matcher.end() - matcher.start(),
				attributes, true);
		}
	}

	private static SimpleAttributeSet attributes(Color color) {
		SimpleAttributeSet attributes = new SimpleAttributeSet();
		StyleConstants.setForeground(attributes, color);
		return attributes;
	}
}
