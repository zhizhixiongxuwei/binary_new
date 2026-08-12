package com.binaryscan.javachecker.service;

import static com.binaryscan.javachecker.service.CheckerConstants.PRODUCT;
import static com.binaryscan.javachecker.service.CheckerConstants.RESPONSE_SCHEMA;
import static com.binaryscan.javachecker.service.CheckerConstants.RULESET;
import static com.binaryscan.javachecker.service.CheckerConstants.VERSION;

import java.util.List;

import com.binaryscan.javachecker.api.AnalysisMetadata;
import com.binaryscan.javachecker.api.AnalysisResponse;

public final class ResponseFactory {
    private ResponseFactory() {
    }

    public static AnalysisResponse terminal(AnalysisMetadata metadata, String status, String code, String message) {
        int total = metadata.files() == null ? 0 : metadata.files().size();
        return new AnalysisResponse(
                RESPONSE_SCHEMA,
                metadata.analysisId(),
                status,
                new AnalysisResponse.Identity(PRODUCT, VERSION, RULESET),
                metadata.inputSha256().toLowerCase(java.util.Locale.ROOT),
                metadata.bundleSha256().toLowerCase(java.util.Locale.ROOT),
                new AnalysisResponse.Coverage(total, 0, 0, 0, total),
                new AnalysisResponse.Summary(0, 1, false, false),
                List.of(),
                List.of(new AnalysisResponse.Diagnostic(
                        Utf8Text.required(code, 128, "analysis_failed"),
                        Utf8Text.message(message), "ERROR", null, null)));
    }
}
