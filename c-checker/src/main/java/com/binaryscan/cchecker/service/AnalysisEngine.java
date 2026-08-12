package com.binaryscan.cchecker.service;

import com.binaryscan.cchecker.api.AnalysisResponse;

public interface AnalysisEngine {
    AnalysisResponse analyze(ValidatedRequest request, AnalysisRunContext context);
}
