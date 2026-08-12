package com.binaryscan.javachecker.engine;

import java.util.List;

import com.binaryscan.javachecker.api.AnalysisResponse;

record RuleEvaluation(List<AnalysisResponse.Finding> findings, boolean truncated, long estimatedBytes) {
}
