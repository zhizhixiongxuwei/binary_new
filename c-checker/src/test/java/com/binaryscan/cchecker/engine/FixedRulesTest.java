package com.binaryscan.cchecker.engine;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import com.binaryscan.cchecker.api.AnalysisResponse;
import com.binaryscan.cchecker.service.AnalysisRunContext;
import com.binaryscan.cchecker.service.CheckerLimits;
import com.binaryscan.cchecker.service.FunctionSlice;

class FixedRulesTest {
    private final CheckerLimits limits = new CheckerLimits(
            128L * 1024 * 1024, 3000, 10000, 1000, 1024, Duration.ofMinutes(10));
    private final FunctionParser parser = new FunctionParser(new FunctionRuleEvaluator(limits), limits);

    @Test
    void emitsAllFifteenFixedRuleClassesFromAntlrParseTree() {
        String source = """
                int sample(char *cmd, char *fmt, char *p) {
                  char buf[4];
                  char local;
                  char *wrong = malloc(sizeof(wrong));
                  int z = 1 / 0;
                  gets(buf);
                  strcpy(buf, p);
                  scanf("%s", buf);
                  printf(fmt);
                  system(cmd);
                  buf[4] = 1;
                  z = buf[5];
                  free(&local);
                  free(p + 1);
                  tmpnam(buf);
                  read(0, buf, 4);
                  MD5_Init(p);
                  chmod("file", 0777);
                  return &local;
                }
                """;
        FunctionSlice function = new FunctionSlice(
                new AnalysisResponse.Function("result-1", "0x1000", "sample"),
                20,
                39,
                0,
                source.getBytes(java.nio.charset.StandardCharsets.UTF_8).length,
                source);

        FunctionParseResult result = parser.parse(function, new AnalysisRunContext("rules", Duration.ofMinutes(1)), 100);
        Set<String> emitted = result.findings().stream()
                .map(AnalysisResponse.Finding::ruleId)
                .collect(Collectors.toSet());

        assertThat(result.parsed()).isTrue();
        assertThat(FunctionRuleEvaluator.RULE_IDS).hasSize(15);
        assertThat(emitted).containsExactlyInAnyOrderElementsOf(FunctionRuleEvaluator.RULE_IDS);
        assertThat(result.findings()).allSatisfy(finding -> {
            assertThat(finding.cwe()).matches("CWE-[0-9]+");
            assertThat(finding.severity()).isIn("LOW", "MEDIUM", "HIGH", "CRITICAL");
            assertThat(finding.location().startLine()).isGreaterThanOrEqualTo(20);
            assertThat(finding.location().startColumn()).isPositive();
            assertThat(finding.snippet().getBytes(java.nio.charset.StandardCharsets.UTF_8).length)
                    .isLessThanOrEqualTo(1024);
        });
    }

    @Test
    void evaluatesPointerStateAtTheFreeCallInsteadOfAtFunctionEnd() {
        Set<String> beforeIncrement = ruleIds("""
                void sample(char *p) {
                  free(p);
                  p++;
                }
                """);
        assertThat(beforeIncrement).doesNotContain("cwe-761-offset-free");

        Set<String> beforeHeapAssignment = ruleIds("""
                void sample(void) {
                  int local;
                  int *p;
                  p = &local;
                  free(p);
                  p = malloc(1);
                }
                """);
        assertThat(beforeHeapAssignment).contains("cwe-590-invalid-free");
    }

    @Test
    void doesNotResetPointerStateWhenAssigningThroughThePointer() {
        Set<String> offsetPointer = ruleIds("""
                void sample(char *p) {
                  p++;
                  p[0] = 0;
                  free(p);
                }
                """);
        assertThat(offsetPointer).contains("cwe-761-offset-free");

        Set<String> stackPointer = ruleIds("""
                void sample(void) {
                  int local;
                  int *p = &local;
                  *p = 0;
                  free(p);
                }
                """);
        assertThat(stackPointer).contains("cwe-590-invalid-free");
    }

    @Test
    void tracksEachArrayDimensionAndDoesNotTreatAnElementReturnAsAStackAddress() {
        Set<String> emitted = ruleIds("""
                int sample(void) {
                  int a[2][5];
                  return a[1][4];
                }
                """);

        assertThat(emitted)
                .doesNotContain("cwe-125-oob-read", "cwe-787-oob-write", "cwe-562-stack-address");
    }

    @Test
    void classifiesNestedArrayIndexesAsReadsRatherThanWrites() {
        Set<String> emitted = ruleIds("""
                void sample(void) {
                  int src[4];
                  int dst[4];
                  dst[src[4]] = 0;
                }
                """);

        assertThat(emitted).contains("cwe-125-oob-read").doesNotContain("cwe-787-oob-write");
    }

    private Set<String> ruleIds(String source) {
        FunctionSlice function = new FunctionSlice(
                new AnalysisResponse.Function("result-regression", "0x2000", "sample"),
                1,
                (int) Math.max(1, source.lines().count()),
                0,
                source.getBytes(java.nio.charset.StandardCharsets.UTF_8).length,
                source);
        FunctionParseResult result = parser.parse(
                function,
                new AnalysisRunContext("regression", Duration.ofMinutes(1)),
                100);
        assertThat(result.parsed()).isTrue();
        return result.findings().stream().map(AnalysisResponse.Finding::ruleId).collect(Collectors.toSet());
    }
}
