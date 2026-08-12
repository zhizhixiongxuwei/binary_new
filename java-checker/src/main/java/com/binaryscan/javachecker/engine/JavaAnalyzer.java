package com.binaryscan.javachecker.engine;

import static com.binaryscan.javachecker.service.CheckerConstants.PRODUCT;
import static com.binaryscan.javachecker.service.CheckerConstants.RESPONSE_SCHEMA;
import static com.binaryscan.javachecker.service.CheckerConstants.RULESET;
import static com.binaryscan.javachecker.service.CheckerConstants.VERSION;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.springframework.stereotype.Component;

import com.binaryscan.javachecker.api.AnalysisResponse;
import com.binaryscan.javachecker.service.CheckerLimits;
import com.binaryscan.javachecker.service.SourceFile;
import com.binaryscan.javachecker.service.Utf8Text;
import com.binaryscan.javachecker.service.ValidatedRequest;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParseStart;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.Problem;
import com.github.javaparser.Providers;
import com.github.javaparser.ast.CompilationUnit;

@Component
public class JavaAnalyzer {
    private final CheckerLimits limits;
    private final JavaRuleEvaluator rules;

    public JavaAnalyzer(CheckerLimits limits, JavaRuleEvaluator rules) {
        this.limits = limits;
        this.rules = rules;
    }

    public AnalysisResponse analyze(ValidatedRequest request, AnalysisRunContext context) {
        JavaParser parser = new JavaParser(new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.BLEEDING_EDGE)
                .setCharacterEncoding(java.nio.charset.StandardCharsets.UTF_8)
                .setStoreTokens(true));

        List<AnalysisResponse.Finding> findings = new ArrayList<>();
        List<AnalysisResponse.Diagnostic> diagnostics = new ArrayList<>();
        ResponseBudget responseBudget = new ResponseBudget(limits.maxResponseBytes());
        boolean findingsTruncated = false;
        boolean diagnosticsTruncated = false;
        int parsed = 0;
        int recovered = 0;
        int analyzed = 0;
        int failed = 0;

        for (SourceFile file : request.files()) {
            context.checkpoint();
            if (file.byteLength() > limits.maxFileBytes()) {
                failed++;
                diagnosticsTruncated |= !addDiagnostic(diagnostics, responseBudget, new AnalysisResponse.Diagnostic(
                        "file_too_large",
                        "file exceeds the configured per-file analysis limit of " + limits.maxFileBytes() + " bytes",
                        "ERROR", file.identity(), null));
                continue;
            }

            ParseResult<CompilationUnit> result;
            try {
                result = parser.parse(ParseStart.COMPILATION_UNIT, Providers.provider(file.source()));
            } catch (RuntimeException error) {
                failed++;
                diagnosticsTruncated |= !addDiagnostic(diagnostics, responseBudget, new AnalysisResponse.Diagnostic(
                        "parser_failed", safeMessage(error), "ERROR", file.identity(), null));
                continue;
            }

            if (result.getResult().isEmpty()) {
                failed++;
                diagnosticsTruncated |= addProblems(result.getProblems(), file, diagnostics, responseBudget);
                if (result.getProblems().isEmpty()) {
                    diagnosticsTruncated |= !addDiagnostic(diagnostics, responseBudget,
                            new AnalysisResponse.Diagnostic(
                            "parser_no_ast", "JavaParser did not produce a compilation unit", "ERROR",
                            file.identity(), null));
                }
                continue;
            }

            parsed++;
            CompilationUnit unit = result.getResult().get();
            if (!result.getProblems().isEmpty()) {
                recovered++;
                diagnosticsTruncated |= addProblems(result.getProblems(), file, diagnostics, responseBudget);
            }
            try {
                RuleEvaluation evaluation = rules.evaluate(
                        unit, file, context, limits.maxFindings() - findings.size(), responseBudget.remaining());
                findings.addAll(evaluation.findings());
                responseBudget.consume(evaluation.estimatedBytes());
                findingsTruncated |= evaluation.truncated();
                analyzed++;
            } catch (java.util.concurrent.CancellationException cancelled) {
                throw cancelled;
            } catch (RuntimeException error) {
                diagnosticsTruncated |= !addDiagnostic(diagnostics, responseBudget, new AnalysisResponse.Diagnostic(
                        "rule_evaluation_failed", safeMessage(error), "ERROR", file.identity(), null));
            }
        }

        findings.sort(Comparator
                .comparing((AnalysisResponse.Finding finding) -> finding.file().logicalPath(),
                        JavaAnalyzer::compareUtf8)
                .thenComparingInt(finding -> finding.location().startLine())
                .thenComparingInt(finding -> finding.location().startColumn())
                .thenComparing(AnalysisResponse.Finding::ruleId));

        boolean sourcePartial = "partial".equals(request.metadata().projectStatus());
        String status;
        if (analyzed == 0) {
            status = "failed";
        } else if (sourcePartial || recovered > 0 || failed > 0 || analyzed < parsed
                || findingsTruncated || diagnosticsTruncated) {
            status = "partial";
        } else {
            status = "complete";
        }

        return new AnalysisResponse(
                RESPONSE_SCHEMA,
                request.metadata().analysisId(),
                status,
                new AnalysisResponse.Identity(PRODUCT, VERSION, RULESET),
                request.metadata().inputSha256().toLowerCase(java.util.Locale.ROOT),
                request.metadata().bundleSha256().toLowerCase(java.util.Locale.ROOT),
                new AnalysisResponse.Coverage(request.files().size(), analyzed, parsed, recovered, failed),
                new AnalysisResponse.Summary(
                        findings.size(), diagnostics.size(), findingsTruncated, diagnosticsTruncated),
                List.copyOf(findings),
                List.copyOf(diagnostics));
    }

    private boolean addProblems(
            List<Problem> problems,
            SourceFile file,
            List<AnalysisResponse.Diagnostic> diagnostics,
            ResponseBudget responseBudget) {
        boolean truncated = false;
        for (Problem problem : problems) {
            Integer line = problem.getLocation()
                    .flatMap(tokenRange -> tokenRange.getBegin().getRange())
                    .map(range -> range.begin.line)
                    .orElse(null);
            if (!addDiagnostic(diagnostics, responseBudget, new AnalysisResponse.Diagnostic(
                    "java_parse_problem", Utf8Text.message(problem.getMessage()),
                    "WARNING", file.identity(), line))) {
                truncated = true;
            }
        }
        return truncated;
    }

    private boolean addDiagnostic(
            List<AnalysisResponse.Diagnostic> diagnostics,
            ResponseBudget responseBudget,
            AnalysisResponse.Diagnostic diagnostic) {
        if (diagnostics.size() >= limits.maxDiagnostics()) {
            return false;
        }
        long bytes = JsonSize.diagnostic(diagnostic);
        if (!responseBudget.tryConsume(bytes)) {
            return false;
        }
        diagnostics.add(diagnostic);
        return true;
    }

    private static String safeMessage(Throwable error) {
        String message = error.getMessage();
        if (message == null || message.isBlank()) {
            message = error.getClass().getSimpleName();
        }
        int newline = message.indexOf('\n');
        return Utf8Text.message(newline >= 0 ? message.substring(0, newline) : message);
    }

    private static int compareUtf8(String left, String right) {
        return java.util.Arrays.compareUnsigned(
                left.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                right.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static final class ResponseBudget {
        private static final long RESPONSE_OVERHEAD_RESERVE = 64L * 1024;
        private final long limit;
        private long used;

        private ResponseBudget(long maxResponseBytes) {
            this.limit = Math.max(0, maxResponseBytes - RESPONSE_OVERHEAD_RESERVE);
        }

        private long remaining() {
            return Math.max(0, limit - used);
        }

        private boolean tryConsume(long bytes) {
            if (bytes < 0 || bytes > remaining()) {
                return false;
            }
            used += bytes;
            return true;
        }

        private void consume(long bytes) {
            if (!tryConsume(bytes)) {
                throw new IllegalStateException("rule evaluator exceeded its response byte budget");
            }
        }
    }
}
