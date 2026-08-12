package com.binaryscan.cchecker.engine;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.Token;
import org.springframework.stereotype.Component;

import com.binaryscan.cchecker.api.AnalysisResponse;
import com.binaryscan.cchecker.grammar.CParser;
import com.binaryscan.cchecker.service.AnalysisRunContext;
import com.binaryscan.cchecker.service.CheckerLimits;
import com.binaryscan.cchecker.service.FunctionSlice;

@Component
public class FunctionRuleEvaluator {
    private static final int SNIPPET_CONTEXT_LINES = 3;
    private static final int SNIPPET_CHECKPOINT_CHARACTERS = 64 * 1024;

    public static final Set<String> RULE_IDS = Set.of(
            "cwe-242-gets",
            "cwe-120-bounds",
            "cwe-134-format",
            "cwe-78-command",
            "cwe-787-oob-write",
            "cwe-125-oob-read",
            "cwe-562-stack-address",
            "cwe-590-invalid-free",
            "cwe-761-offset-free",
            "cwe-369-zero-divisor",
            "cwe-377-temp-file",
            "cwe-252-unchecked-return",
            "cwe-131-size-calculation",
            "cwe-327-328-weak-crypto",
            "cwe-732-permissions");

    private static final Set<String> UNSAFE_COPY = Set.of("strcpy", "strcat", "sprintf", "vsprintf");
    private static final Set<String> SCANF = Set.of(
            "scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf", "wscanf", "fwscanf", "swscanf");
    private static final Set<String> TEMP_APIS = Set.of("tmpnam", "tmpnam_r", "tempnam", "mktemp", "tmpfile");
    private static final Set<String> CHECKED_RETURN_APIS = Set.of(
            "malloc", "calloc", "realloc", "fopen", "open", "openat", "read", "write", "recv", "send",
            "system", "popen", "scanf", "fscanf", "sscanf", "close", "remove", "rename", "chdir", "chmod",
            "fchmod", "setuid", "seteuid", "setgid", "setegid", "pthread_create");
    private static final Set<String> ALLOCATORS = Set.of("malloc", "calloc", "realloc", "strdup", "strndup");
    private static final Set<String> ASSIGNMENT_OPERATORS = Set.of(
            "=", "*=", "/=", "%=", "+=", "-=", "<<=", ">>=", "&=", "^=", "|=");

    private final CheckerLimits limits;

    public FunctionRuleEvaluator(CheckerLimits limits) {
        this.limits = limits;
    }

    public RuleEvaluation evaluate(
            FunctionAst ast,
            FunctionSlice function,
            AnalysisRunContext context,
            int findingCapacity) {
        Evaluation evaluation = new Evaluation(
                function, context, Math.max(0, findingCapacity), limits.maxSnippetBytes());
        Symbols symbols = symbols(ast);
        List<CallSite> calls = calls(ast);
        List<ArrayAccess> accesses = arrayAccesses(ast);

        evaluateCalls(ast, calls, symbols, evaluation);
        evaluateArrayBounds(ast, accesses, symbols, evaluation);
        evaluateReturns(ast, symbols, evaluation);
        evaluateZeroDivisors(ast, evaluation);

        evaluation.findings.sort((left, right) -> {
            int line = Integer.compare(left.location().startLine(), right.location().startLine());
            if (line != 0) {
                return line;
            }
            int column = Integer.compare(left.location().startColumn(), right.location().startColumn());
            return column != 0 ? column : left.ruleId().compareTo(right.ruleId());
        });
        return new RuleEvaluation(List.copyOf(evaluation.findings), evaluation.truncated);
    }

    private void evaluateCalls(
            FunctionAst ast,
            List<CallSite> calls,
            Symbols symbols,
            Evaluation evaluation) {
        for (CallSite call : calls) {
            evaluation.context.checkpoint();
            String name = call.name.toLowerCase(Locale.ROOT);

            if ("gets".equals(name)) {
                evaluation.emit("CWE-242", "cwe-242-gets", "HIGH", call.start, call.stop,
                        "gets cannot bound input and must not be used");
            }

            if (UNSAFE_COPY.contains(name)) {
                evaluation.emit("CWE-120", "cwe-120-bounds", "HIGH", call.start, call.stop,
                        call.name + " does not enforce a destination bound");
            } else if (SCANF.contains(name)) {
                int formatIndex = scanfFormatIndex(name);
                if (formatIndex < call.arguments.size()
                        && TokenTools.isStringLiteral(call.arguments.get(formatIndex))
                        && hasUnboundedStringConversion(stringLiteralValue(call.arguments.get(formatIndex)))) {
                    evaluation.emit("CWE-120", "cwe-120-bounds", "HIGH", call.start, call.stop,
                            call.name + " uses an unbounded %s conversion");
                }
            }

            int formatIndex = printfFormatIndex(name);
            if (formatIndex >= 0 && formatIndex < call.arguments.size()
                    && !TokenTools.isStringLiteral(call.arguments.get(formatIndex))) {
                evaluation.emit("CWE-134", "cwe-134-format", "HIGH", call.start, call.stop,
                        call.name + " receives a non-literal format string");
            }

            if (("system".equals(name) || "popen".equals(name)) && !call.arguments.isEmpty()
                    && !TokenTools.isStringLiteral(call.arguments.get(0))) {
                evaluation.emit("CWE-78", "cwe-78-command", "HIGH", call.start, call.stop,
                        call.name + " receives a non-literal command");
            }

            if (TEMP_APIS.contains(name)) {
                evaluation.emit("CWE-377", "cwe-377-temp-file", "MEDIUM", call.start, call.stop,
                        call.name + " uses an insecure temporary-file API");
            }

            String weakCwe = weakCryptoCwe(call.name);
            if (weakCwe != null) {
                evaluation.emit(weakCwe, "cwe-327-328-weak-crypto", "MEDIUM", call.start, call.stop,
                        call.name + " selects a weak cryptographic primitive");
            }

            if (CHECKED_RETURN_APIS.contains(name) && isDiscardedCall(ast, call)) {
                evaluation.emit("CWE-252", "cwe-252-unchecked-return", "MEDIUM", call.start, call.stop,
                        "return value from " + call.name + " is ignored");
            }

            evaluateFree(call, name, symbols, evaluation);
            evaluateAllocationSize(ast, call, name, symbols, evaluation);
            evaluatePermissions(call, name, evaluation);
        }
    }

    private void evaluateFree(CallSite call, String name, Symbols symbols, Evaluation evaluation) {
        if (!"free".equals(name) || call.arguments.isEmpty()) {
            return;
        }
        List<Token> argument = TokenTools.stripOuterParentheses(call.arguments.get(0));
        if (argument.isEmpty()) {
            return;
        }
        String firstName = TokenTools.isIdentifier(argument.get(0)) ? argument.get(0).getText() : null;
        PointerState pointerState = symbols.pointerStateAt(call.start.getTokenIndex());
        boolean explicitOffset = containsTopLevel(argument, "+")
                || containsTopLevel(argument, "-")
                || (argument.size() >= 3 && TokenTools.text(argument.get(0), "&")
                        && TokenTools.isIdentifier(argument.get(1)) && TokenTools.text(argument.get(2), "["))
                || (firstName != null && pointerState.offsetPointers.contains(firstName));
        if (explicitOffset) {
            evaluation.emit("CWE-761", "cwe-761-offset-free", "HIGH", call.start, call.stop,
                    "free is called with an offset pointer");
            return;
        }

        boolean address = TokenTools.text(argument.get(0), "&");
        boolean literal = TokenTools.isStringLiteral(argument) || TokenTools.integer(argument).isPresent();
        boolean stackArray = firstName != null && symbols.arrays.containsKey(firstName);
        boolean knownNonHeap = firstName != null && pointerState.nonHeapPointers.contains(firstName);
        boolean scalar = firstName != null && symbols.locals.contains(firstName)
                && !symbols.pointers.contains(firstName) && !symbols.arrays.containsKey(firstName);
        if (address || literal || stackArray || knownNonHeap || scalar) {
            evaluation.emit("CWE-590", "cwe-590-invalid-free", "HIGH", call.start, call.stop,
                    "free is called with storage that was not heap allocated");
        }
    }

    private void evaluateAllocationSize(
            FunctionAst ast,
            CallSite call,
            String name,
            Symbols symbols,
            Evaluation evaluation) {
        if (!("malloc".equals(name) || "calloc".equals(name) || "realloc".equals(name))) {
            return;
        }
        int sizeIndex = "malloc".equals(name) ? 0 : 1;
        if (call.arguments.size() <= sizeIndex) {
            return;
        }
        String target = assignedTarget(ast, call);
        if (target != null && symbols.pointers.contains(target)
                && containsSizeofVariable(call.arguments.get(sizeIndex), target)) {
            evaluation.emit("CWE-131", "cwe-131-size-calculation", "HIGH", call.start, call.stop,
                    "allocation uses sizeof(" + target + "), which is the pointer size");
        }
    }

    private void evaluatePermissions(CallSite call, String name, Evaluation evaluation) {
        int modeIndex = switch (name) {
            case "chmod", "fchmod", "creat", "mkdir" -> 1;
            case "open" -> 2;
            case "openat" -> 3;
            default -> -1;
        };
        if (modeIndex < 0 || modeIndex >= call.arguments.size()) {
            return;
        }
        Optional<BigInteger> mode = TokenTools.integer(call.arguments.get(modeIndex));
        if (mode.isPresent() && mode.get().signum() >= 0
                && mode.get().and(BigInteger.valueOf(0002)).signum() != 0) {
            evaluation.emit("CWE-732", "cwe-732-permissions", "MEDIUM", call.start, call.stop,
                    call.name + " grants write permission to other users");
        }
    }

    private void evaluateArrayBounds(
            FunctionAst ast,
            List<ArrayAccess> accesses,
            Symbols symbols,
            Evaluation evaluation) {
        for (ArrayAccess access : accesses) {
            evaluation.context.checkpoint();
            List<Long> dimensions = symbols.arrays.get(access.arrayName);
            if (dimensions == null || access.dimension >= dimensions.size()
                    || access.index.isEmpty()) {
                continue;
            }
            long size = dimensions.get(access.dimension);
            if (size <= 0) {
                continue;
            }
            BigInteger index = access.index.get();
            if (index.signum() >= 0 && index.compareTo(BigInteger.valueOf(size)) < 0) {
                continue;
            }
            boolean write = isWriteAccess(ast, access);
            evaluation.emit(
                    write ? "CWE-787" : "CWE-125",
                    write ? "cwe-787-oob-write" : "cwe-125-oob-read",
                    "HIGH",
                    access.start,
                    access.stop,
                    "array index " + index + " is outside " + access.arrayName + "[" + size + "]");
        }
    }

    private void evaluateReturns(FunctionAst ast, Symbols symbols, Evaluation evaluation) {
        for (CParser.JumpStatementContext jump : ast.jumps()) {
            evaluation.context.checkpoint();
            List<Token> tokens = TokenTools.significant(ast.tokens(), jump);
            if (tokens.size() < 3 || !TokenTools.text(tokens.get(0), "return")) {
                continue;
            }
            List<Token> value = new ArrayList<>(tokens.subList(1, tokens.size()));
            if (!value.isEmpty() && TokenTools.text(value.get(value.size() - 1), ";")) {
                value.remove(value.size() - 1);
            }
            value = TokenTools.stripOuterParentheses(value);
            String returned = null;
            if (value.size() >= 2 && TokenTools.text(value.get(0), "&") && TokenTools.isIdentifier(value.get(1))) {
                returned = value.get(1).getText();
            } else if (value.size() == 1 && TokenTools.isIdentifier(value.get(0))
                    && symbols.arrays.containsKey(value.get(0).getText())) {
                returned = value.get(0).getText();
            } else if (!value.isEmpty() && TokenTools.isIdentifier(value.get(0))
                    && symbols.pointerStateAt(tokens.get(0).getTokenIndex())
                            .stackAddressPointers.contains(value.get(0).getText())) {
                returned = value.get(0).getText();
            }
            if (returned != null && symbols.locals.contains(returned)) {
                evaluation.emit("CWE-562", "cwe-562-stack-address", "HIGH", tokens.get(0), jump.getStop(),
                        "function returns the address of local storage " + returned);
            }
        }
    }

    private void evaluateZeroDivisors(FunctionAst ast, Evaluation evaluation) {
        for (CParser.MultiplicativeExpressionContext expression : ast.multiplicativeExpressions()) {
            evaluation.context.checkpoint();
            List<Token> tokens = TokenTools.significant(ast.tokens(), expression);
            int depth = 0;
            for (int index = 0; index < tokens.size(); index++) {
                String text = tokens.get(index).getText();
                if ("(".equals(text) || "[".equals(text) || "{".equals(text)) {
                    depth++;
                } else if (")".equals(text) || "]".equals(text) || "}".equals(text)) {
                    depth--;
                } else if (depth == 0 && ("/".equals(text) || "%".equals(text))) {
                    int end = index + 1;
                    int operandDepth = 0;
                    while (end < tokens.size()) {
                        String candidate = tokens.get(end).getText();
                        if (("(".equals(candidate) || "[".equals(candidate) || "{".equals(candidate))) {
                            operandDepth++;
                        } else if ((")".equals(candidate) || "]".equals(candidate) || "}".equals(candidate))) {
                            operandDepth--;
                        }
                        if (operandDepth == 0 && end > index + 1
                                && ("*".equals(candidate) || "/".equals(candidate) || "%".equals(candidate))) {
                            break;
                        }
                        end++;
                    }
                    if (TokenTools.isNumericZero(tokens.subList(index + 1, end))) {
                        evaluation.emit("CWE-369", "cwe-369-zero-divisor", "HIGH", tokens.get(index), tokens.get(end - 1),
                                "division or modulo operation has a constant zero divisor");
                    }
                }
            }
        }
    }

    private static Symbols symbols(FunctionAst ast) {
        Symbols symbols = new Symbols();
        for (CParser.DeclarationContext declaration : ast.declarations()) {
            List<Token> tokens = TokenTools.significant(ast.tokens(), declaration);
            if (!tokens.isEmpty() && TokenTools.text(tokens.get(tokens.size() - 1), ";")) {
                tokens = tokens.subList(0, tokens.size() - 1);
            }
            for (List<Token> segment : TokenTools.splitTopLevel(tokens, ",")) {
                int assignment = topLevelOperator(segment, Set.of("="));
                List<Token> declarator = assignment < 0 ? segment : segment.subList(0, assignment);
                String name = lastIdentifier(declarator);
                if (name == null) {
                    continue;
                }
                symbols.locals.add(name);
                int nameIndex = identifierIndex(declarator, name);
                if (containsBefore(declarator, "*", nameIndex)) {
                    symbols.pointers.add(name);
                }
                List<Long> dimensions = arrayDimensions(declarator, nameIndex);
                if (!dimensions.isEmpty()) {
                    symbols.arrays.put(name, dimensions);
                }
                if (assignment >= 0) {
                    symbols.pointerEvents.add(new PointerEvent(
                            segment.get(segment.size() - 1).getTokenIndex(),
                            name,
                            "=",
                            List.copyOf(segment.subList(assignment + 1, segment.size()))));
                }
            }
        }

        for (CParser.AssignmentExpressionContext assignment : ast.assignments()) {
            List<Token> tokens = TokenTools.significant(ast.tokens(), assignment);
            int operator = topLevelOperator(tokens, ASSIGNMENT_OPERATORS);
            if (operator < 1) {
                continue;
            }
            List<Token> left = TokenTools.stripOuterParentheses(tokens.subList(0, operator));
            String target = left.size() == 1 && TokenTools.isIdentifier(left.get(0))
                    ? left.get(0).getText()
                    : null;
            String operatorText = tokens.get(operator).getText();
            if (target != null && ("=".equals(operatorText) || "+=".equals(operatorText)
                    || "-=".equals(operatorText))) {
                symbols.pointerEvents.add(new PointerEvent(
                        tokens.get(tokens.size() - 1).getTokenIndex(),
                        target,
                        operatorText,
                        List.copyOf(tokens.subList(operator + 1, tokens.size()))));
            }
        }
        markIncrementedPointers(ast, symbols);
        symbols.pointerEvents.sort(Comparator.comparingInt(PointerEvent::tokenIndex));
        return symbols;
    }

    private static List<Long> arrayDimensions(List<Token> declarator, int nameIndex) {
        List<Long> dimensions = new ArrayList<>();
        for (int index = nameIndex + 1; index < declarator.size(); index++) {
            if (!TokenTools.text(declarator.get(index), "[")) {
                continue;
            }
            int close = TokenTools.matching(declarator, index, "[", "]");
            if (close < 0) {
                break;
            }
            Optional<BigInteger> size = TokenTools.integer(declarator.subList(index + 1, close));
            long value = -1;
            if (size.isPresent() && size.get().signum() > 0 && size.get().bitLength() < 63) {
                value = size.get().longValue();
            }
            dimensions.add(value);
            index = close;
        }
        return List.copyOf(dimensions);
    }

    private static void markIncrementedPointers(FunctionAst ast, Symbols symbols) {
        List<Token> tokens = ast.tokens().getTokens();
        Token previous = null;
        for (Token token : tokens) {
            if (token.getChannel() != Token.DEFAULT_CHANNEL || token.getType() == Token.EOF) {
                continue;
            }
            if (previous != null) {
                boolean postfix = TokenTools.isIdentifier(previous)
                        && (TokenTools.text(token, "++") || TokenTools.text(token, "--"));
                boolean prefix = (TokenTools.text(previous, "++") || TokenTools.text(previous, "--"))
                        && TokenTools.isIdentifier(token);
                if (postfix) {
                    symbols.pointerEvents.add(new PointerEvent(
                            token.getTokenIndex(), previous.getText(), token.getText(), List.of()));
                } else if (prefix) {
                    symbols.pointerEvents.add(new PointerEvent(
                            token.getTokenIndex(), token.getText(), previous.getText(), List.of()));
                }
            }
            previous = token;
        }
    }

    private static void classifyPointerValue(
            String target,
            List<Token> value,
            Symbols symbols,
            PointerState state) {
        for (int index = 0; index + 1 < value.size(); index++) {
            if (TokenTools.isIdentifier(value.get(index)) && TokenTools.text(value.get(index + 1), "(")
                    && ALLOCATORS.contains(TokenTools.lowercaseIdentifier(value.get(index)))) {
                state.heapPointers.add(target);
            }
        }
        List<Token> stripped = TokenTools.stripOuterParentheses(value);
        if (!stripped.isEmpty() && TokenTools.text(stripped.get(0), "&")) {
            state.nonHeapPointers.add(target);
            if (stripped.size() > 1 && TokenTools.isIdentifier(stripped.get(1))
                    && symbols.locals.contains(stripped.get(1).getText())) {
                state.stackAddressPointers.add(target);
            }
        }
        if (!stripped.isEmpty() && TokenTools.isStringLiteral(stripped)) {
            state.nonHeapPointers.add(target);
        }
        if (stripped.size() == 1 && TokenTools.isIdentifier(stripped.get(0))
                && symbols.arrays.containsKey(stripped.get(0).getText())) {
            state.nonHeapPointers.add(target);
            state.stackAddressPointers.add(target);
        }
        if (stripped.size() == 1 && TokenTools.isIdentifier(stripped.get(0))) {
            String source = stripped.get(0).getText();
            if (state.heapPointers.contains(source)) {
                state.heapPointers.add(target);
            }
            if (state.nonHeapPointers.contains(source)) {
                state.nonHeapPointers.add(target);
            }
            if (state.stackAddressPointers.contains(source)) {
                state.stackAddressPointers.add(target);
            }
            if (state.offsetPointers.contains(source)) {
                state.offsetPointers.add(target);
            }
        }
        if (containsTopLevel(stripped, "+") || containsTopLevel(stripped, "-")) {
            state.offsetPointers.add(target);
        }
    }

    private static List<CallSite> calls(FunctionAst ast) {
        List<CallSite> result = new ArrayList<>();
        Set<Integer> starts = new HashSet<>();
        for (CParser.PostfixExpressionContext context : ast.postfixExpressions()) {
            List<Token> tokens = TokenTools.significant(ast.tokens(), context);
            if (tokens.size() < 3 || !TokenTools.isIdentifier(tokens.get(0)) || !TokenTools.text(tokens.get(1), "(")) {
                continue;
            }
            int close = TokenTools.matching(tokens, 1, "(", ")");
            if (close < 0 || !starts.add(tokens.get(0).getTokenIndex())) {
                continue;
            }
            result.add(new CallSite(
                    tokens.get(0).getText(),
                    tokens.get(0),
                    tokens.get(close),
                    TokenTools.splitArguments(tokens, 1, close),
                    context));
        }
        return result;
    }

    private static List<ArrayAccess> arrayAccesses(FunctionAst ast) {
        List<ArrayAccess> result = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (CParser.PostfixExpressionContext context : ast.postfixExpressions()) {
            List<Token> tokens = TokenTools.significant(ast.tokens(), context);
            if (tokens.size() < 4 || !TokenTools.isIdentifier(tokens.get(0))) {
                continue;
            }
            int dimension = 0;
            for (int index = 1; index < tokens.size(); index++) {
                if (!TokenTools.text(tokens.get(index), "[")) {
                    continue;
                }
                int close = TokenTools.matching(tokens, index, "[", "]");
                if (close < 0) {
                    break;
                }
                String key = tokens.get(0).getTokenIndex() + ":" + tokens.get(index).getTokenIndex();
                if (seen.add(key)) {
                    result.add(new ArrayAccess(
                            tokens.get(0).getText(),
                            TokenTools.integer(tokens.subList(index + 1, close)),
                            dimension,
                            tokens.get(0),
                            tokens.get(close),
                            context));
                }
                dimension++;
                index = close;
            }
        }
        return result;
    }

    private static boolean isWriteAccess(FunctionAst ast, ArrayAccess access) {
        CParser.AssignmentExpressionContext assignment = TokenTools.ancestor(
                access.context, CParser.AssignmentExpressionContext.class);
        while (assignment != null) {
            List<Token> tokens = TokenTools.significant(ast.tokens(), assignment);
            int operator = topLevelOperator(tokens, ASSIGNMENT_OPERATORS);
            if (operator > 0 && access.stop.getTokenIndex() < tokens.get(operator).getTokenIndex()) {
                List<Token> left = TokenTools.stripOuterParentheses(tokens.subList(0, operator));
                for (Token token : left) {
                    if (TokenTools.isIdentifier(token)) {
                        return token.getTokenIndex() == access.start.getTokenIndex();
                    }
                }
            }
            assignment = TokenTools.ancestor(assignment, CParser.AssignmentExpressionContext.class);
        }
        List<Token> postfix = TokenTools.significant(ast.tokens(), access.context);
        if (postfix.isEmpty() || postfix.get(0).getTokenIndex() != access.start.getTokenIndex()) {
            return false;
        }
        return postfix.stream().anyMatch(token -> TokenTools.text(token, "++") || TokenTools.text(token, "--"));
    }

    private static boolean isDiscardedCall(FunctionAst ast, CallSite call) {
        CParser.ExpressionStatementContext statement = TokenTools.ancestor(
                call.context, CParser.ExpressionStatementContext.class);
        if (statement == null) {
            return false;
        }
        List<Token> tokens = TokenTools.significant(ast.tokens(), statement);
        if (!tokens.isEmpty() && TokenTools.text(tokens.get(tokens.size() - 1), ";")) {
            tokens = tokens.subList(0, tokens.size() - 1);
        }
        tokens = TokenTools.stripOuterParentheses(tokens);
        return !tokens.isEmpty()
                && tokens.get(0).getTokenIndex() == call.start.getTokenIndex()
                && tokens.get(tokens.size() - 1).getTokenIndex() == call.stop.getTokenIndex();
    }

    private static String assignedTarget(FunctionAst ast, CallSite call) {
        CParser.AssignmentExpressionContext assignment = TokenTools.ancestor(
                call.context, CParser.AssignmentExpressionContext.class);
        while (assignment != null) {
            List<Token> tokens = TokenTools.significant(ast.tokens(), assignment);
            int operator = topLevelOperator(tokens, Set.of("="));
            if (operator > 0 && call.start.getTokenIndex() > tokens.get(operator).getTokenIndex()) {
                return lastIdentifier(tokens.subList(0, operator));
            }
            assignment = TokenTools.ancestor(assignment, CParser.AssignmentExpressionContext.class);
        }
        CParser.DeclarationContext declaration = TokenTools.ancestor(call.context, CParser.DeclarationContext.class);
        if (declaration != null) {
            List<Token> tokens = TokenTools.significant(ast.tokens(), declaration);
            int callIndex = -1;
            for (int index = 0; index < tokens.size(); index++) {
                if (tokens.get(index).getTokenIndex() == call.start.getTokenIndex()) {
                    callIndex = index;
                    break;
                }
            }
            if (callIndex > 0) {
                int equals = -1;
                for (int index = callIndex - 1; index >= 0; index--) {
                    if (TokenTools.text(tokens.get(index), "=")) {
                        equals = index;
                        break;
                    }
                    if (TokenTools.text(tokens.get(index), ",")) {
                        break;
                    }
                }
                if (equals > 0) {
                    return lastIdentifier(tokens.subList(0, equals));
                }
            }
        }
        return null;
    }

    private static boolean containsSizeofVariable(List<Token> tokens, String variable) {
        for (int index = 0; index < tokens.size(); index++) {
            if (!TokenTools.text(tokens.get(index), "sizeof")) {
                continue;
            }
            int candidate = index + 1;
            if (candidate < tokens.size() && TokenTools.text(tokens.get(candidate), "(")) {
                candidate++;
            }
            if (candidate < tokens.size() && TokenTools.isIdentifier(tokens.get(candidate))
                    && variable.equals(tokens.get(candidate).getText())) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasUnboundedStringConversion(String format) {
        for (int index = 0; index < format.length(); index++) {
            if (format.charAt(index) != '%') {
                continue;
            }
            if (index + 1 < format.length() && format.charAt(index + 1) == '%') {
                index++;
                continue;
            }
            int cursor = index + 1;
            if (cursor < format.length() && format.charAt(cursor) == '*') {
                cursor++;
            }
            boolean width = false;
            while (cursor < format.length() && Character.isDigit(format.charAt(cursor))) {
                width = true;
                cursor++;
            }
            while (cursor < format.length() && "hljztL".indexOf(format.charAt(cursor)) >= 0) {
                cursor++;
            }
            if (cursor < format.length() && format.charAt(cursor) == 's' && !width) {
                return true;
            }
        }
        return false;
    }

    private static String stringLiteralValue(List<Token> tokens) {
        StringBuilder result = new StringBuilder();
        for (Token token : TokenTools.stripOuterParentheses(tokens)) {
            if (token.getType() != CParser.StringLiteral) {
                continue;
            }
            String text = token.getText();
            int quote = text.indexOf('"');
            if (quote >= 0 && text.endsWith("\"")) {
                result.append(text, quote + 1, text.length() - 1);
            }
        }
        return result.toString();
    }

    private static int scanfFormatIndex(String name) {
        return switch (name) {
            case "fscanf", "sscanf", "vfscanf", "vsscanf", "fwscanf", "swscanf" -> 1;
            default -> 0;
        };
    }

    private static int printfFormatIndex(String name) {
        return switch (name) {
            case "printf", "vprintf", "wprintf", "vwprintf" -> 0;
            case "fprintf", "vfprintf", "dprintf", "vdprintf", "sprintf", "vsprintf", "fwprintf", "vfwprintf" -> 1;
            case "snprintf", "vsnprintf", "swprintf", "vswprintf" -> 2;
            case "syslog", "vsyslog" -> 1;
            default -> -1;
        };
    }

    private static String weakCryptoCwe(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.contains("md5") || lower.contains("sha1") || lower.equals("sha") || lower.startsWith("sha_")) {
            return "CWE-328";
        }
        if (lower.startsWith("des_") || lower.startsWith("rc4") || lower.contains("evp_des")
                || lower.contains("evp_rc4") || lower.equals("crypt") || lower.equals("ecb_encrypt")) {
            return "CWE-327";
        }
        return null;
    }

    private static int topLevelOperator(List<Token> tokens, Set<String> operators) {
        int parens = 0;
        int brackets = 0;
        int braces = 0;
        for (int index = 0; index < tokens.size(); index++) {
            String text = tokens.get(index).getText();
            if (operators.contains(text) && parens == 0 && brackets == 0 && braces == 0) {
                return index;
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
        return -1;
    }

    private static boolean containsTopLevel(List<Token> tokens, String operator) {
        return topLevelOperator(tokens, Set.of(operator)) >= 0;
    }

    private static String lastIdentifier(List<Token> tokens) {
        for (int index = tokens.size() - 1; index >= 0; index--) {
            if (TokenTools.isIdentifier(tokens.get(index))) {
                return tokens.get(index).getText();
            }
        }
        return null;
    }

    private static int identifierIndex(List<Token> tokens, String name) {
        for (int index = tokens.size() - 1; index >= 0; index--) {
            if (TokenTools.isIdentifier(tokens.get(index)) && name.equals(tokens.get(index).getText())) {
                return index;
            }
        }
        return -1;
    }

    private static boolean containsBefore(List<Token> tokens, String text, int limit) {
        for (int index = 0; index >= 0 && index < limit; index++) {
            if (TokenTools.text(tokens.get(index), text)) {
                return true;
            }
        }
        return false;
    }

    private static final class Evaluation {
        private final FunctionSlice function;
        private final AnalysisRunContext context;
        private final int capacity;
        private final int maxSnippetBytes;
        private final List<AnalysisResponse.Finding> findings = new ArrayList<>();
        private final Set<String> deduplication = new LinkedHashSet<>();
        private SnippetSource snippetSource;
        private boolean truncated;

        private Evaluation(FunctionSlice function, AnalysisRunContext context, int capacity, int maxSnippetBytes) {
            this.function = function;
            this.context = context;
            this.capacity = capacity;
            this.maxSnippetBytes = maxSnippetBytes;
        }

        private void emit(
                String cwe,
                String ruleId,
                String severity,
                Token start,
                Token stop,
                String message) {
            context.checkpoint();
            if (!RULE_IDS.contains(ruleId) || start == null) {
                throw new IllegalArgumentException("unknown rule id " + ruleId);
            }
            int originalLine = function.startLine() + Math.max(1, start.getLine()) - 1;
            originalLine = Math.max(function.startLine(), Math.min(function.endLine(), originalLine));
            int startColumn = Math.max(1, start.getCharPositionInLine() + 1);
            AnalysisResponse.Location location = location(originalLine, startColumn, stop == null ? start : stop);
            String key = ruleId + ":" + location.startLine() + ":" + location.startColumn();
            if (!deduplication.add(key)) {
                return;
            }
            if (findings.size() >= capacity) {
                truncated = true;
                return;
            }
            findings.add(new AnalysisResponse.Finding(
                    cwe,
                    ruleId,
                    severity,
                    function.identity(),
                    location,
                    bounded(message, 512),
                    snippet(start)));
        }

        private AnalysisResponse.Location location(int startLine, int startColumn, Token stop) {
            String text = stop.getText() == null ? "" : stop.getText();
            int newlines = 0;
            int lastLineLength = 0;
            for (int index = 0; index < text.length(); index++) {
                char value = text.charAt(index);
                if (value == '\n') {
                    newlines++;
                    lastLineLength = 0;
                } else if (value != '\r') {
                    lastLineLength++;
                }
            }
            int endLine = function.startLine() + Math.max(1, stop.getLine()) - 1 + newlines;
            endLine = Math.max(startLine, Math.min(function.endLine(), endLine));
            int endColumn = newlines == 0
                    ? stop.getCharPositionInLine() + Math.max(1, text.length()) + 1
                    : Math.max(1, lastLineLength + 1);
            if (endLine == startLine) {
                endColumn = Math.max(startColumn, endColumn);
            }
            return new AnalysisResponse.Location(startLine, startColumn, endLine, endColumn);
        }

        private String snippet(Token token) {
            if (snippetSource == null) {
                snippetSource = SnippetSource.prepare(function.source(), context::checkpoint);
            }
            return snippetSource.context(
                    token.getLine(), token.getCharPositionInLine(), maxSnippetBytes, context::checkpoint);
        }
    }

    static String contextSnippet(String source, int hitLine, int hitColumn, int maximumBytes) {
        if (source == null || source.isEmpty() || maximumBytes <= 0) {
            return "";
        }
        return SnippetSource.prepare(source, null).context(hitLine, hitColumn, maximumBytes, null);
    }

    private static final class SnippetSource {
        private final String source;
        private final List<SnippetLine> lines;

        private SnippetSource(String source, List<SnippetLine> lines) {
            this.source = source;
            this.lines = lines;
        }

        private static SnippetSource prepare(String source, Runnable checkpoint) {
            if (source == null || source.isEmpty()) {
                return new SnippetSource("", List.of());
            }

            List<SnippetLine> lines = new ArrayList<>();
            StringBuilder sanitized = new StringBuilder(Math.min(source.length(), 4096));
            int lineStart = 0;
            int sanitizedBytes = 0;
            int charactersSinceCheckpoint = 0;
            for (int offset = 0; offset < source.length();) {
                int codePoint = source.codePointAt(offset);
                int characters = Character.charCount(codePoint);
                if (codePoint == '\n') {
                    lines.add(new SnippetLine(lineStart, offset, sanitized.toString(), sanitizedBytes));
                    sanitized.setLength(0);
                    sanitizedBytes = 0;
                    lineStart = offset + characters;
                } else {
                    sanitizedBytes += appendSanitizedCodePoint(sanitized, codePoint);
                }
                offset += characters;
                charactersSinceCheckpoint += characters;
                if (charactersSinceCheckpoint >= SNIPPET_CHECKPOINT_CHARACTERS) {
                    runCheckpoint(checkpoint);
                    charactersSinceCheckpoint = 0;
                }
            }
            if (lineStart < source.length()) {
                lines.add(new SnippetLine(lineStart, source.length(), sanitized.toString(), sanitizedBytes));
            }
            if (lines.isEmpty()) {
                lines.add(new SnippetLine(0, 0, "", 0));
            }
            return new SnippetSource(source, List.copyOf(lines));
        }

        private String context(
                int hitLine,
                int hitColumn,
                int maximumBytes,
                Runnable checkpoint) {
            if (lines.isEmpty() || maximumBytes <= 0) {
                return "";
            }
            int hitIndex = hitLine <= 1 ? 0 : Math.min(lines.size() - 1, hitLine - 1);
            int start = Math.max(0, hitIndex - SNIPPET_CONTEXT_LINES);
            int end = Math.min(lines.size() - 1, hitIndex + SNIPPET_CONTEXT_LINES);
            int contextBytes = contextBytes(start, end);

            while (contextBytes > maximumBytes && (start < hitIndex || end > hitIndex)) {
                int linesAbove = hitIndex - start;
                int linesBelow = end - hitIndex;
                if (linesAbove > linesBelow) {
                    start++;
                } else if (linesBelow > linesAbove) {
                    end--;
                } else if (lines.get(start).utf8Bytes() >= lines.get(end).utf8Bytes()) {
                    start++;
                } else {
                    end--;
                }
                contextBytes = contextBytes(start, end);
            }
            if (contextBytes <= maximumBytes) {
                return joinLines(start, end);
            }

            SnippetLine line = lines.get(hitIndex);
            int sanitizedAnchor = sanitizedAnchor(line, Math.max(0, hitColumn), checkpoint);
            return boundedUtf8AroundAnchor(line.value(), sanitizedAnchor, maximumBytes, checkpoint);
        }

        private int contextBytes(int start, int end) {
            int bytes = end - start;
            for (int index = start; index <= end; index++) {
                bytes += lines.get(index).utf8Bytes();
            }
            return bytes;
        }

        private String joinLines(int start, int end) {
            StringBuilder result = new StringBuilder();
            for (int index = start; index <= end; index++) {
                if (index > start) {
                    result.append('\n');
                }
                result.append(lines.get(index).value());
            }
            return result.toString();
        }

        private int sanitizedAnchor(SnippetLine line, int hitColumn, Runnable checkpoint) {
            int rawCodePoints = 0;
            int sanitizedCharacters = 0;
            int charactersSinceCheckpoint = 0;
            for (int offset = line.sourceStart();
                    offset < line.sourceEnd() && rawCodePoints < hitColumn;) {
                int codePoint = source.codePointAt(offset);
                int characters = Character.charCount(codePoint);
                sanitizedCharacters += sanitizedCharacterCount(codePoint);
                offset += characters;
                rawCodePoints++;
                charactersSinceCheckpoint += characters;
                if (charactersSinceCheckpoint >= SNIPPET_CHECKPOINT_CHARACTERS) {
                    runCheckpoint(checkpoint);
                    charactersSinceCheckpoint = 0;
                }
            }
            return sanitizedCharacters;
        }
    }

    private record SnippetLine(int sourceStart, int sourceEnd, String value, int utf8Bytes) {
    }

    private static int appendSanitizedCodePoint(StringBuilder target, int codePoint) {
        if (codePoint == '\r' || codePoint == '\t') {
            target.append(' ');
            return 1;
        }
        if (Character.isISOControl(codePoint) || isUnsafeSnippetFormatControl(codePoint)) {
            return 0;
        }
        target.appendCodePoint(codePoint);
        return utf8Length(codePoint);
    }

    private static int sanitizedCharacterCount(int codePoint) {
        if (codePoint == '\r' || codePoint == '\t') {
            return 1;
        }
        if (Character.isISOControl(codePoint) || isUnsafeSnippetFormatControl(codePoint)) {
            return 0;
        }
        return Character.charCount(codePoint);
    }

    private static boolean isUnsafeSnippetFormatControl(int codePoint) {
        // These invisible format controls can reorder or conceal source when rendered.
        return codePoint == 0x00ad
                || codePoint == 0x061c
                || codePoint == 0x180e
                || (codePoint >= 0x200b && codePoint <= 0x200f)
                || (codePoint >= 0x202a && codePoint <= 0x202e)
                || (codePoint >= 0x2060 && codePoint <= 0x206f)
                || codePoint == 0xfeff
                || (codePoint >= 0xfff9 && codePoint <= 0xfffb)
                || codePoint == 0xe0001
                || (codePoint >= 0xe0020 && codePoint <= 0xe007f);
    }

    private static void runCheckpoint(Runnable checkpoint) {
        if (checkpoint != null) {
            checkpoint.run();
        }
    }

    private static String boundedUtf8AroundAnchor(
            String value,
            int anchor,
            int maximumBytes,
            Runnable checkpoint) {
        if (value.isEmpty() || maximumBytes <= 0) {
            return "";
        }

        int boundedAnchor = Math.max(0, Math.min(anchor, value.length()));
        if (boundedAnchor == value.length()) {
            boundedAnchor = value.offsetByCodePoints(value.length(), -1);
        } else if (boundedAnchor > 0
                && Character.isLowSurrogate(value.charAt(boundedAnchor))
                && Character.isHighSurrogate(value.charAt(boundedAnchor - 1))) {
            boundedAnchor--;
        }
        int anchorCodePoint = value.codePointAt(boundedAnchor);
        int anchorBytes = utf8Length(anchorCodePoint);
        if (anchorBytes > maximumBytes) {
            return "";
        }

        int start = boundedAnchor;
        int end = boundedAnchor + Character.charCount(anchorCodePoint);
        int bytes = anchorBytes;
        int traversedCharacters = Character.charCount(anchorCodePoint);
        int preferredRightBytes = Math.max(anchorBytes, maximumBytes - maximumBytes / 4);
        while (end < value.length()) {
            int nextCodePoint = value.codePointAt(end);
            int nextBytes = utf8Length(nextCodePoint);
            if (nextBytes > preferredRightBytes - bytes) {
                break;
            }
            bytes += nextBytes;
            int characters = Character.charCount(nextCodePoint);
            end += characters;
            traversedCharacters += characters;
            if (traversedCharacters >= SNIPPET_CHECKPOINT_CHARACTERS) {
                runCheckpoint(checkpoint);
                traversedCharacters = 0;
            }
        }
        while (start > 0) {
            int previousCodePoint = value.codePointBefore(start);
            int previousBytes = utf8Length(previousCodePoint);
            if (previousBytes > maximumBytes - bytes) {
                break;
            }
            bytes += previousBytes;
            int characters = Character.charCount(previousCodePoint);
            start -= characters;
            traversedCharacters += characters;
            if (traversedCharacters >= SNIPPET_CHECKPOINT_CHARACTERS) {
                runCheckpoint(checkpoint);
                traversedCharacters = 0;
            }
        }
        while (end < value.length()) {
            int nextCodePoint = value.codePointAt(end);
            int nextBytes = utf8Length(nextCodePoint);
            if (nextBytes > maximumBytes - bytes) {
                break;
            }
            bytes += nextBytes;
            int characters = Character.charCount(nextCodePoint);
            end += characters;
            traversedCharacters += characters;
            if (traversedCharacters >= SNIPPET_CHECKPOINT_CHARACTERS) {
                runCheckpoint(checkpoint);
                traversedCharacters = 0;
            }
        }
        return value.substring(start, end);
    }

    private static int utf8Length(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private static int utf8Length(int codePoint) {
        if (codePoint <= 0x7f) {
            return 1;
        }
        if (codePoint <= 0x7ff) {
            return 2;
        }
        if (codePoint <= 0xffff) {
            return 3;
        }
        return 4;
    }

    private static String bounded(String value, int maximumCharacters) {
        return value.length() <= maximumCharacters ? value : value.substring(0, maximumCharacters);
    }

    static String boundedUtf8(String value, int maximumBytes) {
        if (value.getBytes(StandardCharsets.UTF_8).length <= maximumBytes) {
            return value;
        }
        StringBuilder result = new StringBuilder();
        int bytes = 0;
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            String character = new String(Character.toChars(codePoint));
            int characterBytes = character.getBytes(StandardCharsets.UTF_8).length;
            if (bytes + characterBytes > maximumBytes) {
                break;
            }
            result.append(character);
            bytes += characterBytes;
            offset += Character.charCount(codePoint);
        }
        return result.toString();
    }

    private static final class Symbols {
        private final Set<String> locals = new HashSet<>();
        private final Set<String> pointers = new HashSet<>();
        private final Map<String, List<Long>> arrays = new HashMap<>();
        private final List<PointerEvent> pointerEvents = new ArrayList<>();

        private PointerState pointerStateAt(int tokenIndex) {
            PointerState state = new PointerState();
            for (PointerEvent event : pointerEvents) {
                if (event.tokenIndex > tokenIndex) {
                    break;
                }
                if ("=".equals(event.operator)) {
                    state.reset(event.target);
                    classifyPointerValue(event.target, event.value, this, state);
                } else if ("+=".equals(event.operator) || "-=".equals(event.operator)
                        || "++".equals(event.operator) || "--".equals(event.operator)) {
                    state.offsetPointers.add(event.target);
                }
            }
            return state;
        }
    }

    private static final class PointerState {
        private final Set<String> heapPointers = new HashSet<>();
        private final Set<String> nonHeapPointers = new HashSet<>();
        private final Set<String> stackAddressPointers = new HashSet<>();
        private final Set<String> offsetPointers = new HashSet<>();

        private void reset(String name) {
            heapPointers.remove(name);
            nonHeapPointers.remove(name);
            stackAddressPointers.remove(name);
            offsetPointers.remove(name);
        }
    }

    private record PointerEvent(int tokenIndex, String target, String operator, List<Token> value) {
    }

    private record CallSite(
            String name,
            Token start,
            Token stop,
            List<List<Token>> arguments,
            CParser.PostfixExpressionContext context) {
    }

    private record ArrayAccess(
            String arrayName,
            Optional<BigInteger> index,
            int dimension,
            Token start,
            Token stop,
            CParser.PostfixExpressionContext context) {
    }
}
