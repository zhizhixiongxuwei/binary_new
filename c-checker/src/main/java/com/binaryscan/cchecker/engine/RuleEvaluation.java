package com.binaryscan.cchecker.engine;

import java.util.List;

import com.binaryscan.cchecker.api.AnalysisResponse;

record RuleEvaluation(List<AnalysisResponse.Finding> findings, boolean truncated) {
}
