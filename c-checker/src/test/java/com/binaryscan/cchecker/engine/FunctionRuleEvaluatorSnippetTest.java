package com.binaryscan.cchecker.engine;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.Test;

import com.binaryscan.cchecker.api.AnalysisResponse;
import com.binaryscan.cchecker.service.AnalysisRunContext;
import com.binaryscan.cchecker.service.CheckerLimits;
import com.binaryscan.cchecker.service.FunctionSlice;

class FunctionRuleEvaluatorSnippetTest {
    @Test
    void includesThreeSourceLinesOnEachSideOfAMiddleHit() {
        String source = String.join("\n",
                "line 1",
                "line 2",
                "line 3",
                "line 4",
                "gets(buffer);",
                "line 6",
                "line 7",
                "line 8",
                "line 9");

        String snippet = FunctionRuleEvaluator.contextSnippet(source, 5, 0, 1024);

        assertThat(snippet).isEqualTo(String.join("\n",
                "line 2",
                "line 3",
                "line 4",
                "gets(buffer);",
                "line 6",
                "line 7",
                "line 8"));
    }

    @Test
    void clampsContextAtTheFirstAndLastSourceLines() {
        String source = String.join("\n",
                "first();",
                "line 2",
                "line 3",
                "line 4",
                "line 5",
                "last();");

        assertThat(FunctionRuleEvaluator.contextSnippet(source, 1, 0, 1024))
                .isEqualTo(String.join("\n", "first();", "line 2", "line 3", "line 4"));
        assertThat(FunctionRuleEvaluator.contextSnippet(source, 6, 0, 1024))
                .isEqualTo(String.join("\n", "line 3", "line 4", "line 5", "last();"));
    }

    @Test
    void dropsOversizedOuterContextBeforeTheCompleteHitLine() {
        String longLine = "\u754c".repeat(400);
        String hitLine = "  gets(buffer);";
        String source = String.join("\n",
                longLine, longLine, longLine, hitLine, longLine, longLine, longLine);

        String snippet = FunctionRuleEvaluator.contextSnippet(source, 4, 2, 64);

        assertThat(snippet).isEqualTo(hitLine);
        assertThat(snippet.getBytes(StandardCharsets.UTF_8).length).isLessThanOrEqualTo(64);
    }

    @Test
    void cropsAnOversizedHitLineAroundTheFindingOnUtf8Boundaries() {
        String hit = "gets(buffer);";
        String hitLine = "\u754c".repeat(100) + hit + "\u754c".repeat(100);

        String snippet = FunctionRuleEvaluator.contextSnippet(hitLine, 1, 100, 96);

        assertThat(snippet).contains(hit).doesNotContain("\ufffd");
        assertThat(snippet.getBytes(StandardCharsets.UTF_8).length).isLessThanOrEqualTo(96);
    }

    @Test
    void cropsAMultiMegabyteHitLineUsingOnlyTheBoundedAnchorWindow() {
        String prefix = "a".repeat(4 * 1024 * 1024);
        String hit = "gets(buffer);";
        String source = prefix + hit + "b".repeat(4 * 1024 * 1024);

        String snippet = FunctionRuleEvaluator.contextSnippet(source, 1, prefix.length(), 1024);

        assertThat(snippet).contains(hit);
        assertThat(snippet.getBytes(StandardCharsets.UTF_8)).hasSize(1024);
    }

    @Test
    void filtersUnsafeControlsWithoutAddingSourceMarkers() {
        String source = "before\tvalue\u0000\u202e\n"
                + "gets(\u2066buffer\u2069);\n"
                + "after\rvalue\u200b";

        String snippet = FunctionRuleEvaluator.contextSnippet(source, 2, 0, 1024);

        assertThat(snippet).isEqualTo("before value\ngets(buffer);\nafter value");
        assertThat(snippet).doesNotContain("\u0000", "\u202e", "\u2066", "\u2069", "\u200b", "...");
    }

    @Test
    void realAntlrFindingCarriesTheExpectedSourceContext() {
        String source = String.join("\n",
                "int sample(char *buffer) {",
                "  int value = 0;",
                "  value++;",
                "  value++;",
                "  gets(buffer);",
                "  value++;",
                "  value++;",
                "  value++;",
                "  return value;",
                "}") + "\n";
        CheckerLimits limits = new CheckerLimits(
                128L * 1024 * 1024, 3000, 10000, 1000, 1024, Duration.ofMinutes(10));
        FunctionParser parser = new FunctionParser(new FunctionRuleEvaluator(limits), limits);
        FunctionSlice function = new FunctionSlice(
                new AnalysisResponse.Function("result-1", "0x1000", "sample"),
                20,
                29,
                0,
                source.getBytes(StandardCharsets.UTF_8).length,
                source);

        FunctionParseResult result = parser.parse(
                function,
                new AnalysisRunContext("snippet-integration", Duration.ofMinutes(1)),
                100);
        AnalysisResponse.Finding finding = result.findings().stream()
                .filter(value -> "cwe-242-gets".equals(value.ruleId()))
                .findFirst()
                .orElseThrow();

        assertThat(result.parsed()).isTrue();
        assertThat(finding.location().startLine()).isEqualTo(24);
        assertThat(finding.snippet()).isEqualTo(String.join("\n",
                "  int value = 0;",
                "  value++;",
                "  value++;",
                "  gets(buffer);",
                "  value++;",
                "  value++;",
                "  value++;"));
    }
}
