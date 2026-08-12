package com.binaryscan.cchecker.api;

import java.util.List;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AnalysisMetadata(
        String schemaVersion,
        String analysisId,
        String projectId,
        String canonicalSha256,
        Long canonicalSizeBytes,
        String projectStatus,
        String engineName,
        String engineVersion,
        List<FunctionMetadata> functions) {

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record FunctionMetadata(
            String resultId,
            String address,
            String name,
            String sha256,
            Long offsetBytes,
            Long lengthBytes,
            Integer startLine,
            Integer endLine) {
    }
}
