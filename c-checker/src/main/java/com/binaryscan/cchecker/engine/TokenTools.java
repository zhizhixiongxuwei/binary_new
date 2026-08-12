package com.binaryscan.cchecker.engine;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.tree.ParseTree;

import com.binaryscan.cchecker.grammar.CParser;

final class TokenTools {
    private TokenTools() {
    }

    static List<Token> significant(CommonTokenStream stream, ParserRuleContext context) {
        if (context == null || context.getStart() == null || context.getStop() == null) {
            return List.of();
        }
        return significant(stream, context.getStart().getTokenIndex(), context.getStop().getTokenIndex());
    }

    static List<Token> significant(CommonTokenStream stream, int start, int stop) {
        List<Token> result = new ArrayList<>();
        for (Token token : stream.getTokens(start, stop)) {
            if (token.getChannel() == Token.DEFAULT_CHANNEL && token.getType() != Token.EOF) {
                result.add(token);
            }
        }
        return result;
    }

    static boolean isIdentifier(Token token) {
        return token != null && token.getType() == CParser.Identifier;
    }

    static boolean text(Token token, String expected) {
        return token != null && expected.equals(token.getText());
    }

    static int matching(List<Token> tokens, int openIndex, String open, String close) {
        int depth = 0;
        for (int index = openIndex; index < tokens.size(); index++) {
            String text = tokens.get(index).getText();
            if (open.equals(text)) {
                depth++;
            } else if (close.equals(text) && --depth == 0) {
                return index;
            }
        }
        return -1;
    }

    static List<List<Token>> splitArguments(List<Token> tokens, int openIndex, int closeIndex) {
        if (closeIndex == openIndex + 1) {
            return List.of();
        }
        List<List<Token>> arguments = new ArrayList<>();
        int parens = 0;
        int brackets = 0;
        int braces = 0;
        int start = openIndex + 1;
        for (int index = start; index < closeIndex; index++) {
            String text = tokens.get(index).getText();
            switch (text) {
                case "(" -> parens++;
                case ")" -> parens--;
                case "[" -> brackets++;
                case "]" -> brackets--;
                case "{" -> braces++;
                case "}" -> braces--;
                case "," -> {
                    if (parens == 0 && brackets == 0 && braces == 0) {
                        arguments.add(List.copyOf(tokens.subList(start, index)));
                        start = index + 1;
                    }
                }
                default -> {
                }
            }
        }
        arguments.add(List.copyOf(tokens.subList(start, closeIndex)));
        return List.copyOf(arguments);
    }

    static List<List<Token>> splitTopLevel(List<Token> tokens, String delimiter) {
        List<List<Token>> parts = new ArrayList<>();
        int parens = 0;
        int brackets = 0;
        int braces = 0;
        int start = 0;
        for (int index = 0; index < tokens.size(); index++) {
            String text = tokens.get(index).getText();
            if (delimiter.equals(text) && parens == 0 && brackets == 0 && braces == 0) {
                parts.add(List.copyOf(tokens.subList(start, index)));
                start = index + 1;
                continue;
            }
            switch (text) {
                case "(" -> parens++;
                case ")" -> parens--;
                case "[" -> brackets++;
                case "]" -> brackets--;
                case "{" -> braces++;
                case "}" -> braces--;
                default -> {
                }
            }
        }
        parts.add(List.copyOf(tokens.subList(start, tokens.size())));
        return parts;
    }

    static List<Token> stripOuterParentheses(List<Token> input) {
        List<Token> tokens = input;
        while (tokens.size() >= 2 && text(tokens.get(0), "(")
                && matching(tokens, 0, "(", ")") == tokens.size() - 1) {
            tokens = tokens.subList(1, tokens.size() - 1);
        }
        return tokens;
    }

    static boolean isStringLiteral(List<Token> input) {
        List<Token> tokens = stripOuterParentheses(input);
        return !tokens.isEmpty() && tokens.stream().allMatch(token -> token.getType() == CParser.StringLiteral);
    }

    static Optional<BigInteger> integer(List<Token> input) {
        List<Token> tokens = stripOuterParentheses(input);
        boolean negative = false;
        if (!tokens.isEmpty() && (text(tokens.get(0), "+") || text(tokens.get(0), "-"))) {
            negative = text(tokens.get(0), "-");
            tokens = tokens.subList(1, tokens.size());
        }
        if (tokens.size() != 1) {
            return Optional.empty();
        }
        String literal = tokens.get(0).getText().replace("'", "");
        literal = literal.replaceFirst("(?i)(u|l)+$", "");
        try {
            int radix;
            String digits;
            if (literal.startsWith("0x") || literal.startsWith("0X")) {
                radix = 16;
                digits = literal.substring(2);
            } else if (literal.startsWith("0b") || literal.startsWith("0B")) {
                radix = 2;
                digits = literal.substring(2);
            } else if (literal.length() > 1 && literal.startsWith("0")) {
                radix = 8;
                digits = literal.substring(1);
            } else {
                radix = 10;
                digits = literal;
            }
            BigInteger value = new BigInteger(digits.isEmpty() ? "0" : digits, radix);
            return Optional.of(negative ? value.negate() : value);
        } catch (NumberFormatException ignored) {
            return Optional.empty();
        }
    }

    static boolean isNumericZero(List<Token> input) {
        Optional<BigInteger> integer = integer(input);
        if (integer.isPresent()) {
            return integer.get().signum() == 0;
        }
        List<Token> tokens = stripOuterParentheses(input);
        if (tokens.isEmpty()) {
            return false;
        }
        String literal = compactText(tokens);
        if (literal.startsWith("+") || literal.startsWith("-")) {
            literal = literal.substring(1);
        }
        literal = literal.replaceFirst("(?i)[fl]$", "");
        try {
            return Double.parseDouble(literal) == 0.0d;
        } catch (NumberFormatException ignored) {
            return false;
        }
    }

    static <T extends ParseTree> T ancestor(ParseTree node, Class<T> type) {
        ParseTree current = node == null ? null : node.getParent();
        while (current != null) {
            if (type.isInstance(current)) {
                return type.cast(current);
            }
            current = current.getParent();
        }
        return null;
    }

    static String compactText(List<Token> tokens) {
        StringBuilder result = new StringBuilder();
        for (Token token : tokens) {
            result.append(token.getText());
        }
        return result.toString();
    }

    static String lowercaseIdentifier(Token token) {
        return token.getText().toLowerCase(Locale.ROOT);
    }
}
