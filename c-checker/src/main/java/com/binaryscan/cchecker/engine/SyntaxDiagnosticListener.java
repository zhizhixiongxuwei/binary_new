package com.binaryscan.cchecker.engine;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;

import com.binaryscan.cchecker.api.AnalysisResponse;
import com.binaryscan.cchecker.service.AnalysisRunContext;
import com.binaryscan.cchecker.service.FunctionSlice;

final class SyntaxDiagnosticListener extends BaseErrorListener {
    private final FunctionSlice function;
    private final AnalysisRunContext context;
    private final int limit;
    private final List<AnalysisResponse.Diagnostic> diagnostics = new ArrayList<>();
    private final Set<String> seen = new HashSet<>();
    private int errorCount;

    SyntaxDiagnosticListener(FunctionSlice function, AnalysisRunContext context, int limit) {
        this.function = function;
        this.context = context;
        this.limit = limit;
    }

    @Override
    public void syntaxError(
            Recognizer<?, ?> recognizer,
            Object offendingSymbol,
            int line,
            int charPositionInLine,
            String message,
            RecognitionException exception) {
        context.checkpoint();
        errorCount++;
        int originalLine = function.startLine() + Math.max(1, line) - 1;
        originalLine = Math.max(function.startLine(), Math.min(function.endLine(), originalLine));
        String clean = clean(message);
        String key = originalLine + ":" + charPositionInLine + ":" + clean;
        if (diagnostics.size() < limit && seen.add(key)) {
            diagnostics.add(new AnalysisResponse.Diagnostic(
                    function.identity().resultId(),
                    "syntax_error",
                    clean,
                    originalLine));
        }
    }

    int errorCount() {
        return errorCount;
    }

    List<AnalysisResponse.Diagnostic> diagnostics() {
        return List.copyOf(diagnostics);
    }

    private static String clean(String message) {
        if (message == null || message.isBlank()) {
            return "C syntax error";
        }
        StringBuilder sanitized = new StringBuilder(message.length());
        message.codePoints().forEach(codePoint -> {
            if (codePoint == '\r' || codePoint == '\n' || Character.isISOControl(codePoint)) {
                sanitized.append(' ');
            } else {
                sanitized.appendCodePoint(codePoint);
            }
        });
        String singleLine = sanitized.toString().strip();
        if (singleLine.isEmpty()) {
            return "C syntax error";
        }
        return singleLine.length() <= 512 ? singleLine : singleLine.substring(0, 512);
    }
}
