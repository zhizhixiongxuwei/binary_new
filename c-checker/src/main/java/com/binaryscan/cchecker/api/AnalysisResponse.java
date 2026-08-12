package com.binaryscan.cchecker.api;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AnalysisResponse(
        String schemaVersion,
        String analysisId,
        String status,
        Checker checker,
        Coverage coverage,
        Summary summary,
        List<Finding> findings,
        List<Diagnostic> diagnostics) {

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Checker(String name, String version, String rulesetVersion) {
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Coverage(int totalFunctions, int parsedFunctions, int failedFunctions) {
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Summary(
            int findingCount,
            int diagnosticCount,
            boolean findingsTruncated,
            boolean diagnosticsTruncated) {
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Finding(
            String cwe,
            String ruleId,
            String severity,
            Function function,
            Location location,
            String message,
            String snippet) {
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Function(String resultId, String address, String name) {
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Location(int startLine, int startColumn, int endLine, int endColumn) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Diagnostic(String functionResultId, String code, String message, Integer line) {
    }
}
