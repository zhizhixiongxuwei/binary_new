package com.binaryscan.javachecker.api;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AnalysisMetadata(
        String schemaVersion,
        String analysisId,
        String inputSha256,
        String bundleSha256,
        String sourceManifestSha256,
        String projectId,
        String language,
        String projectStatus,
        List<FileMetadata> files) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record FileMetadata(
            String resultId,
            String logicalPath,
            String binaryName,
            String displayName,
            String sha256,
            @JsonAlias("offset") Long offsetBytes,
            @JsonAlias("length") Long lengthBytes) {
    }
}
