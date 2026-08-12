package com.binaryscan.javachecker.engine;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.Test;

import com.binaryscan.javachecker.TestProject;
import com.binaryscan.javachecker.api.AnalysisResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.binaryscan.javachecker.service.CheckerLimits;
import com.binaryscan.javachecker.service.SourceValidator;

class PartialAndLimitsTest {
    @Test
    void sourceMarkedPartialKeepsFindingsAndCoverage() {
        CheckerLimits limits = CheckerLimits.defaults();
        TestProject.Request raw = TestProject.oneFile("""
                import java.security.MessageDigest;
                class Partial { void run() throws Exception { MessageDigest.getInstance("MD5"); } }
                """, "partial");
        var request = new SourceValidator(limits)
                .validate(raw.metadata().analysisId(), raw.metadata(), raw.bundle());

        AnalysisResponse response = analyzer(limits).analyze(request, new AnalysisRunContext(() -> false));

        assertThat(response.status()).isEqualTo("partial");
        assertThat(response.findings()).extracting(AnalysisResponse.Finding::ruleId)
                .contains("java-weak-message-digest");
        assertThat(response.coverage().filesParsed() + response.coverage().filesFailed())
                .isEqualTo(response.coverage().filesTotal());
        assertThat(response.coverage().filesAnalyzed()).isLessThanOrEqualTo(response.coverage().filesParsed());
    }

    @Test
    void findingLimitMarksResponsePartial() {
        CheckerLimits limits = limits(1, 1000, 1024, 8 * 1024 * 1024L);
        TestProject.Request raw = TestProject.oneFile("""
                import java.security.MessageDigest;
                class Many { void run() throws Exception {
                  MessageDigest.getInstance("MD5");
                  MessageDigest.getInstance("SHA-1");
                } }
                """);
        var request = new SourceValidator(limits)
                .validate(raw.metadata().analysisId(), raw.metadata(), raw.bundle());

        AnalysisResponse response = analyzer(limits).analyze(request, new AnalysisRunContext(() -> false));

        assertThat(response.findings()).hasSize(1);
        assertThat(response.summary().findingsTruncated()).isTrue();
        assertThat(response.status()).isEqualTo("partial");
    }

    @Test
    void oversizedFileFailsWithoutParsing() {
        CheckerLimits limits = limits(100, 100, 1024, 8);
        TestProject.Request raw = TestProject.oneFile("class TooLarge {}\n");
        var request = new SourceValidator(limits)
                .validate(raw.metadata().analysisId(), raw.metadata(), raw.bundle());

        AnalysisResponse response = analyzer(limits).analyze(request, new AnalysisRunContext(() -> false));

        assertThat(response.status()).isEqualTo("failed");
        assertThat(response.coverage().filesFailed()).isEqualTo(1);
        assertThat(response.coverage().filesParsed()).isZero();
        assertThat(response.diagnostics()).extracting(AnalysisResponse.Diagnostic::code)
                .containsExactly("file_too_large");
    }

    @Test
    void snippetsRemainOnUtf8BoundariesAndWithinByteLimit() {
        CheckerLimits limits = limits(100, 100, 96, 8 * 1024 * 1024L);
        String source = "import java.security.MessageDigest; class Wide { void run() throws Exception { String x = \""
                + "\u754c".repeat(600)
                + "\"; MessageDigest.getInstance(\"MD5\"); } }\n";
        TestProject.Request raw = TestProject.oneFile(source);
        var request = new SourceValidator(limits)
                .validate(raw.metadata().analysisId(), raw.metadata(), raw.bundle());

        AnalysisResponse response = analyzer(limits).analyze(request, new AnalysisRunContext(() -> false));

        assertThat(response.findings()).hasSize(1);
        byte[] snippet = response.findings().get(0).snippet().getBytes(StandardCharsets.UTF_8);
        assertThat(snippet).hasSizeLessThanOrEqualTo(96);
        assertThat(response.findings().get(0).snippet()).doesNotContain("\ufffd");
    }

    @Test
    void responseByteBudgetTruncatesFindingsBeforeSerializationLimit() throws Exception {
        CheckerLimits limits = new CheckerLimits(
                128L * 1024 * 1024, 3000, 8L * 1024 * 1024, 10000, 1000, 1024,
                70L * 1024, Duration.ofMinutes(10), Duration.ofSeconds(2));
        StringBuilder source = new StringBuilder("import java.security.MessageDigest; class Many { void run() throws Exception {");
        for (int i = 0; i < 500; i++) {
            source.append("MessageDigest.getInstance(\"MD5\");");
        }
        source.append("} }");
        TestProject.Request raw = TestProject.oneFile(source.toString());
        var request = new SourceValidator(limits)
                .validate(raw.metadata().analysisId(), raw.metadata(), raw.bundle());

        AnalysisResponse response = analyzer(limits).analyze(request, new AnalysisRunContext(() -> false));
        byte[] json = new ObjectMapper().writeValueAsBytes(response);

        assertThat(response.status()).isEqualTo("partial");
        assertThat(response.summary().findingsTruncated()).isTrue();
        assertThat((long) json.length).isLessThanOrEqualTo(limits.maxResponseBytes());
    }

    private static JavaAnalyzer analyzer(CheckerLimits limits) {
        return new JavaAnalyzer(limits, new JavaRuleEvaluator(limits));
    }

    private static CheckerLimits limits(int findings, int diagnostics, int snippet, long maxFile) {
        return new CheckerLimits(
                128L * 1024 * 1024, 3000, maxFile, findings, diagnostics, snippet,
                32L * 1024 * 1024, Duration.ofMinutes(10), Duration.ofSeconds(2));
    }
}
