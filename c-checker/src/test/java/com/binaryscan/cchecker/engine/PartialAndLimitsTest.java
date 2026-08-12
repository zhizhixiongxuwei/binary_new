package com.binaryscan.cchecker.engine;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.binaryscan.cchecker.api.AnalysisMetadata;
import com.binaryscan.cchecker.api.AnalysisResponse;
import com.binaryscan.cchecker.service.AnalysisRunContext;
import com.binaryscan.cchecker.service.CheckerLimits;
import com.binaryscan.cchecker.service.FunctionSlice;
import com.binaryscan.cchecker.service.ValidatedRequest;

class PartialAndLimitsTest {
    @Test
    void keepsGoodFunctionResultsWhenAnotherFunctionDoesNotParse() {
        CheckerLimits limits = limits(10000, 1000, 1024);
        CAnalyzer analyzer = analyzer(limits);
        FunctionSlice good = function("good", "int good(char *p) { gets(p); return 0; }\n", 10);
        FunctionSlice bad = function("bad", "int bad( {\n", 30);
        ValidatedRequest request = new ValidatedRequest(metadata("partial", "complete"), List.of(good, bad));

        AnalysisResponse response = analyzer.analyze(request, new AnalysisRunContext("partial", Duration.ofMinutes(1)));

        assertThat(response.status()).isEqualTo("partial");
        assertThat(response.coverage().parsedFunctions()).isEqualTo(1);
        assertThat(response.coverage().failedFunctions()).isEqualTo(1);
        assertThat(response.findings()).extracting(AnalysisResponse.Finding::ruleId).contains("cwe-242-gets");
        assertThat(response.diagnostics()).extracting(AnalysisResponse.Diagnostic::code).contains("syntax_error");
        assertThat(response.diagnostics()).filteredOn(diagnostic -> "bad-result".equals(diagnostic.functionResultId()))
                .allSatisfy(diagnostic -> assertThat(diagnostic.line()).isBetween(30, 30));
    }

    @Test
    void capsFindingsAndMarksTheResponsePartial() {
        CheckerLimits limits = limits(1, 1000, 1024);
        CAnalyzer analyzer = analyzer(limits);
        String source = "int many(char *p) {\n gets(p);\n gets(p);\n return 0;\n}\n";
        ValidatedRequest request = new ValidatedRequest(
                metadata("limited", "complete"), List.of(function("many", source, 1)));

        AnalysisResponse response = analyzer.analyze(request, new AnalysisRunContext("limited", Duration.ofMinutes(1)));

        assertThat(response.status()).isEqualTo("partial");
        assertThat(response.findings()).hasSize(1);
        assertThat(response.summary().findingsTruncated()).isTrue();
        assertThat(response.summary().findingCount()).isEqualTo(1);
    }

    @Test
    void capsDiagnosticsAndMarksTruncation() {
        CheckerLimits limits = limits(10000, 1, 1024);
        CAnalyzer analyzer = analyzer(limits);
        ValidatedRequest request = new ValidatedRequest(
                metadata("diagnostic-limit", "complete"),
                List.of(function("bad-one", "int bad_one( {\n", 10),
                        function("bad-two", "int bad_two( {\n", 20)));

        AnalysisResponse response = analyzer.analyze(
                request, new AnalysisRunContext("diagnostic-limit", Duration.ofMinutes(1)));

        assertThat(response.diagnostics()).hasSize(1);
        assertThat(response.summary().diagnosticCount()).isEqualTo(1);
        assertThat(response.summary().diagnosticsTruncated()).isTrue();
        assertThat(response.status()).isEqualTo("failed");
    }

    @Test
    void truncatesSnippetsOnUtf8Boundaries() {
        String value = "\u754c".repeat(600);
        String bounded = FunctionRuleEvaluator.boundedUtf8(value, 1024);
        assertThat(bounded.getBytes(StandardCharsets.UTF_8).length).isLessThanOrEqualTo(1024);
        assertThat(bounded).doesNotContain("\ufffd");
    }

    @Test
    void cancelledTerminalResponseDropsFindingsProducedBeforeCancellation() {
        CheckerLimits limits = limits(10000, 1000, 1024);
        CAnalyzer analyzer = new CAnalyzer(new TerminalStubParser(limits, true, false), limits);
        ValidatedRequest request = new ValidatedRequest(
                metadata("cancelled", "complete"),
                List.of(function("first", "int first(void) { return 0; }\n", 1),
                        function("second", "int second(void) { return 0; }\n", 2)));

        AnalysisResponse response = analyzer.analyze(request, new AnalysisRunContext("cancelled", Duration.ofMinutes(1)));

        assertThat(response.status()).isEqualTo("cancelled");
        assertThat(response.findings()).isEmpty();
        assertThat(response.summary().findingCount()).isZero();
        assertThat(response.summary().findingsTruncated()).isFalse();
    }

    @Test
    void failedTimeoutResponseDropsFindingsProducedBeforeTimeout() {
        CheckerLimits limits = new CheckerLimits(
                128L * 1024 * 1024, 3000, 10000, 1000, 1024, Duration.ofMillis(2));
        CAnalyzer analyzer = new CAnalyzer(new TerminalStubParser(limits, false, true), limits);
        ValidatedRequest request = new ValidatedRequest(
                metadata("timeout", "complete"),
                List.of(function("first", "int first(void) { return 0; }\n", 1),
                        function("second", "int second(void) { return 0; }\n", 2)));

        AnalysisResponse response = analyzer.analyze(request, new AnalysisRunContext("timeout", Duration.ofMillis(2)));

        assertThat(response.status()).isEqualTo("failed");
        assertThat(response.findings()).isEmpty();
        assertThat(response.summary().findingCount()).isZero();
        assertThat(response.diagnostics()).extracting(AnalysisResponse.Diagnostic::code).contains("analysis_timeout");
    }

    private static CAnalyzer analyzer(CheckerLimits limits) {
        FunctionParser parser = new FunctionParser(new FunctionRuleEvaluator(limits), limits);
        return new CAnalyzer(parser, limits);
    }

    private static CheckerLimits limits(int findings, int diagnostics, int snippetBytes) {
        return new CheckerLimits(128L * 1024 * 1024, 3000, findings, diagnostics, snippetBytes, Duration.ofMinutes(10));
    }

    private static FunctionSlice function(String name, String source, int startLine) {
        return new FunctionSlice(
                new AnalysisResponse.Function(name + "-result", "0x1000", name),
                startLine,
                startLine + Math.max(0, (int) source.lines().count() - 1),
                0,
                source.getBytes(StandardCharsets.UTF_8).length,
                source);
    }

    private static AnalysisMetadata metadata(String analysisId, String projectStatus) {
        return new AnalysisMetadata(
                "binaryscan-c-analysis-request/v1",
                analysisId,
                "project",
                "0".repeat(64),
                0L,
                projectStatus,
                "ghidra",
                "12.1.2",
                List.of());
    }

    private static final class TerminalStubParser extends FunctionParser {
        private final boolean cancel;
        private final boolean delay;
        private int calls;

        private TerminalStubParser(CheckerLimits limits, boolean cancel, boolean delay) {
            super(new FunctionRuleEvaluator(limits), limits);
            this.cancel = cancel;
            this.delay = delay;
        }

        @Override
        public FunctionParseResult parse(FunctionSlice function, AnalysisRunContext context, int findingCapacity) {
            calls++;
            if (calls > 1) {
                context.checkpoint();
            }
            AnalysisResponse.Finding finding = new AnalysisResponse.Finding(
                    "CWE-242",
                    "cwe-242-gets",
                    "HIGH",
                    function.identity(),
                    new AnalysisResponse.Location(function.startLine(), 1, function.startLine(), 2),
                    "synthetic finding",
                    "gets(p);");
            if (cancel) {
                context.cancel();
            }
            if (delay) {
                try {
                    Thread.sleep(10);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
            return new FunctionParseResult(true, List.of(), List.of(finding), false);
        }
    }
}
