package com.binaryscan.javachecker.service;

import java.util.List;

import com.binaryscan.javachecker.api.AnalysisMetadata;

public record ValidatedRequest(AnalysisMetadata metadata, List<SourceFile> files) {
}
