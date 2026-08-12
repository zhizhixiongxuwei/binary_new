package com.binaryscan.javachecker.service;

import com.binaryscan.javachecker.api.AnalysisMetadata;
import com.binaryscan.javachecker.api.AnalysisResponse;

public record SourceFile(AnalysisMetadata.FileMetadata metadata, long byteLength, String source) {
    public AnalysisResponse.FileIdentity identity() {
        return new AnalysisResponse.FileIdentity(
                metadata.resultId(), metadata.logicalPath(), metadata.binaryName());
    }
}
