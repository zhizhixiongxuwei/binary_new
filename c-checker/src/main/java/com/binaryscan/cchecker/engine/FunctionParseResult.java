package com.binaryscan.cchecker.engine;

import java.util.List;

import com.binaryscan.cchecker.api.AnalysisResponse;

public record FunctionParseResult(
        boolean parsed,
        List<AnalysisResponse.Diagnostic> diagnostics,
        List<AnalysisResponse.Finding> findings,
        boolean findingsTruncated) {
}
