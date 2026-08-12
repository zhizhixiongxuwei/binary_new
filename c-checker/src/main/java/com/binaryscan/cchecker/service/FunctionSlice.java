package com.binaryscan.cchecker.service;

import com.binaryscan.cchecker.api.AnalysisResponse;

public record FunctionSlice(
        AnalysisResponse.Function identity,
        int startLine,
        int endLine,
        long offsetBytes,
        int lengthBytes,
        String source) {
}
