package com.binaryscan.cchecker.service;

import java.util.List;

import com.binaryscan.cchecker.api.AnalysisMetadata;

public record ValidatedRequest(AnalysisMetadata metadata, List<FunctionSlice> functions) {
}
