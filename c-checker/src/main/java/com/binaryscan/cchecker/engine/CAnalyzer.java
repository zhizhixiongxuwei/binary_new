package com.binaryscan.cchecker.engine;

import static com.binaryscan.cchecker.service.CheckerConstants.NAME;
import static com.binaryscan.cchecker.service.CheckerConstants.RESPONSE_SCHEMA;
import static com.binaryscan.cchecker.service.CheckerConstants.RULESET_VERSION;
import static com.binaryscan.cchecker.service.CheckerConstants.VERSION;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.nio.charset.StandardCharsets;

import org.springframework.stereotype.Component;

import com.binaryscan.cchecker.api.AnalysisResponse;
import com.binaryscan.cchecker.service.AnalysisEngine;
import com.binaryscan.cchecker.service.AnalysisRunContext;
import com.binaryscan.cchecker.service.AnalysisRunContext.AnalysisStoppedException;
import com.binaryscan.cchecker.service.AnalysisRunContext.StopReason;
import com.binaryscan.cchecker.service.CheckerLimits;
import com.binaryscan.cchecker.service.FunctionSlice;
import com.binaryscan.cchecker.service.ValidatedRequest;

@Component
public class CAnalyzer implements AnalysisEngine {
    private static final int RESPONSE_PAYLOAD_BUDGET = 30 * 1024 * 1024;

    private final FunctionParser parser;
    private final CheckerLimits limits;

    public CAnalyzer(FunctionParser parser, CheckerLimits limits) {
        this.parser = parser;
        this.limits = limits;
    }

    @Override
    public AnalysisResponse analyze(ValidatedRequest request, AnalysisRunContext context) {
        List<AnalysisResponse.Finding> findings = new ArrayList<>();
        List<AnalysisResponse.Diagnostic> diagnostics = new ArrayList<>();
        int parsedFunctions = 0;
        int failedFunctions = 0;
        boolean findingsTruncated = false;
        boolean diagnosticsTruncated = false;
        StopReason stopReason = null;
        int estimatedResponseBytes = 4096;

        for (FunctionSlice function : request.functions()) {
            try {
                context.checkpoint();
                int capacity = Math.max(0, limits.maxFindings() - findings.size());
                FunctionParseResult result = parser.parse(function, context, capacity);
                if (result.parsed()) {
                    parsedFunctions++;
                } else {
                    failedFunctions++;
                }
                for (AnalysisResponse.Finding finding : result.findings()) {
                    int findingBytes = estimatedFindingBytes(finding);
                    if (estimatedResponseBytes + findingBytes <= RESPONSE_PAYLOAD_BUDGET) {
                        findings.add(finding);
                        estimatedResponseBytes += findingBytes;
                    } else {
                        findingsTruncated = true;
                    }
                }
                findingsTruncated |= result.findingsTruncated();
                for (AnalysisResponse.Diagnostic diagnostic : result.diagnostics()) {
                    int diagnosticBytes = estimatedDiagnosticBytes(diagnostic);
                    if (diagnostics.size() < limits.maxDiagnostics()
                            && estimatedResponseBytes + diagnosticBytes <= RESPONSE_PAYLOAD_BUDGET) {
                        diagnostics.add(diagnostic);
                        estimatedResponseBytes += diagnosticBytes;
                    } else {
                        diagnosticsTruncated = true;
                    }
                }
            } catch (AnalysisStoppedException stopped) {
                stopReason = stopped.reason();
                break;
            } catch (RuntimeException | StackOverflowError functionFailure) {
                failedFunctions++;
                if (diagnostics.size() < limits.maxDiagnostics()) {
                    diagnostics.add(new AnalysisResponse.Diagnostic(
                            function.identity().resultId(),
                            "function_analysis_error",
                            "function could not be analyzed",
                            function.startLine()));
                } else {
                    diagnosticsTruncated = true;
                }
            }
        }

        if (stopReason == null) {
            try {
                context.checkpoint();
            } catch (AnalysisStoppedException stopped) {
                stopReason = stopped.reason();
            }
        }

        if (stopReason == StopReason.TIMEOUT) {
            if (diagnostics.size() < limits.maxDiagnostics()) {
                diagnostics.add(new AnalysisResponse.Diagnostic(
                        null, "analysis_timeout", "analysis exceeded the 10 minute time limit", null));
            } else {
                diagnosticsTruncated = true;
            }
        }

        findings.sort(Comparator
                .comparingInt((AnalysisResponse.Finding finding) -> finding.location().startLine())
                .thenComparingInt(finding -> finding.location().startColumn())
                .thenComparing(AnalysisResponse.Finding::ruleId));

        String status = status(
                request,
                stopReason,
                parsedFunctions,
                failedFunctions,
                findingsTruncated,
                diagnosticsTruncated);
        if ("failed".equals(status) || "cancelled".equals(status)) {
            findings.clear();
            findingsTruncated = false;
        }
        return new AnalysisResponse(
                RESPONSE_SCHEMA,
                request.metadata().analysisId(),
                status,
                new AnalysisResponse.Checker(NAME, VERSION, RULESET_VERSION),
                new AnalysisResponse.Coverage(request.functions().size(), parsedFunctions, failedFunctions),
                new AnalysisResponse.Summary(
                        findings.size(),
                        diagnostics.size(),
                        findingsTruncated,
                        diagnosticsTruncated),
                List.copyOf(findings),
                List.copyOf(diagnostics));
    }

    private static String status(
            ValidatedRequest request,
            StopReason stopReason,
            int parsedFunctions,
            int failedFunctions,
            boolean findingsTruncated,
            boolean diagnosticsTruncated) {
        if (stopReason == StopReason.CANCELLED) {
            return "cancelled";
        }
        if (stopReason == StopReason.TIMEOUT) {
            return "failed";
        }
        if (!request.functions().isEmpty() && parsedFunctions == 0 && failedFunctions > 0) {
            return "failed";
        }
        if (failedFunctions > 0
                || findingsTruncated
                || diagnosticsTruncated
                || "partial".equals(request.metadata().projectStatus())) {
            return "partial";
        }
        return "succeeded";
    }

    private static int estimatedFindingBytes(AnalysisResponse.Finding finding) {
        return 512
                + estimatedJsonStringBytes(finding.cwe())
                + estimatedJsonStringBytes(finding.ruleId())
                + estimatedJsonStringBytes(finding.severity())
                + estimatedJsonStringBytes(finding.function().resultId())
                + estimatedJsonStringBytes(finding.function().address())
                + estimatedJsonStringBytes(finding.function().name())
                + estimatedJsonStringBytes(finding.message())
                + estimatedJsonStringBytes(finding.snippet());
    }

    private static int estimatedDiagnosticBytes(AnalysisResponse.Diagnostic diagnostic) {
        return 256
                + estimatedJsonStringBytes(diagnostic.functionResultId())
                + estimatedJsonStringBytes(diagnostic.code())
                + estimatedJsonStringBytes(diagnostic.message());
    }

    private static int estimatedJsonStringBytes(String value) {
        if (value == null) {
            return 4;
        }
        int bytes = 2;
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            if (codePoint == '"' || codePoint == '\\') {
                bytes += 2;
            } else if (codePoint < 0x20) {
                bytes += 6;
            } else {
                bytes += new String(Character.toChars(codePoint)).getBytes(StandardCharsets.UTF_8).length;
            }
            offset += Character.charCount(codePoint);
        }
        return bytes;
    }
}
