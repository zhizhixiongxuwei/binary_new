package com.binaryscan.javachecker.api;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AnalysisResponse(
        String schemaVersion,
        String analysisId,
        String status,
        Identity identity,
        String inputSha256,
        String bundleSha256,
        Coverage coverage,
        Summary summary,
        List<Finding> findings,
        List<Diagnostic> diagnostics) {

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Identity(String product, String version, String ruleset) {
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Coverage(
            int filesTotal,
            int filesAnalyzed,
            int filesParsed,
            int filesRecovered,
            int filesFailed) {
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
            String ruleId,
            String cwe,
            String severity,
            String message,
            FileIdentity file,
            Callable callable,
            Location location,
            String snippet,
            int snippetStartLine) {
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record FileIdentity(String resultId, String logicalPath, String binaryName) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Callable(String kind, String typeName, String name, String signature) {
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Location(int startLine, int startColumn, int endLine, int endColumn) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Diagnostic(String code, String message, String severity, FileIdentity file, Integer line) {
    }
}
