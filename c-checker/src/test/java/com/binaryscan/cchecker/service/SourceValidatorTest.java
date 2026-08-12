package com.binaryscan.cchecker.service;

import static com.binaryscan.cchecker.TestRequests.metadata;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.binaryscan.cchecker.api.AnalysisMetadata;
import com.binaryscan.cchecker.api.ApiException;

class SourceValidatorTest {
    private final CheckerLimits limits = new CheckerLimits(1024, 3000, 10000, 1000, 1024, Duration.ofMinutes(10));
    private final SourceValidator validator = new SourceValidator(limits);

    @Test
    void validatesCanonicalAndPerFunctionHashesAndRanges() {
        String source = "int sample(void) {\n  return 0;\n}\n";
        byte[] bytes = source.getBytes(StandardCharsets.UTF_8);

        ValidatedRequest result = validator.validate("valid", metadata("valid", source), bytes);

        assertThat(result.functions()).hasSize(1);
        assertThat(result.functions().get(0).source()).isEqualTo(source);
        assertThat(result.functions().get(0).startLine()).isEqualTo(1);
    }

    @Test
    void validatesCanonicalFunctionRangesWithBannersAndTrailingBlankLines() {
        String prefix = "/* generated */\n";
        String functionSource = "int sample(void) {\n  return 0;\n}\n\n";
        String canonical = prefix + functionSource + "\n";
        byte[] canonicalBytes = canonical.getBytes(StandardCharsets.UTF_8);
        byte[] functionBytes = functionSource.getBytes(StandardCharsets.UTF_8);
        AnalysisMetadata metadata = new AnalysisMetadata(
                "binaryscan-c-analysis-request/v1",
                "canonical-range",
                "project-1",
                com.binaryscan.cchecker.TestRequests.sha256(canonicalBytes),
                (long) canonicalBytes.length,
                "complete",
                "ghidra",
                "12.1.2",
                List.of(new AnalysisMetadata.FunctionMetadata(
                        "result-1",
                        "0x1000",
                        "sample",
                        com.binaryscan.cchecker.TestRequests.sha256(functionBytes),
                        (long) prefix.getBytes(StandardCharsets.UTF_8).length,
                        (long) functionBytes.length,
                        2,
                        5)));

        ValidatedRequest result = validator.validate("canonical-range", metadata, canonicalBytes);

        assertThat(result.functions()).singleElement()
                .satisfies(function -> assertThat(function.source()).isEqualTo(functionSource));
    }

    @Test
    void rejectsCanonicalHashMismatch() {
        String source = "int sample(void) { return 0; }\n";
        AnalysisMetadata valid = metadata("hash", source);
        AnalysisMetadata changed = new AnalysisMetadata(
                valid.schemaVersion(), valid.analysisId(), valid.projectId(), "f".repeat(64), valid.canonicalSizeBytes(),
                valid.projectStatus(), valid.engineName(), valid.engineVersion(), valid.functions());

        assertThatThrownBy(() -> validator.validate("hash", changed, source.getBytes(StandardCharsets.UTF_8)))
                .isInstanceOfSatisfying(ApiException.class, error -> {
                    assertThat(error.status().value()).isEqualTo(422);
                    assertThat(error.code()).isEqualTo("canonical_sha256_mismatch");
                });
    }

    @Test
    void enforcesSourceAndFunctionCountLimits() {
        String source = "int sample(void) { return 0; }\n";
        SourceValidator tinySourceValidator = new SourceValidator(
                new CheckerLimits(4, 3000, 10000, 1000, 1024, Duration.ofMinutes(10)));
        assertThatThrownBy(() -> tinySourceValidator.validate(
                "source-limit", metadata("source-limit", source), source.getBytes(StandardCharsets.UTF_8)))
                .isInstanceOfSatisfying(ApiException.class,
                        error -> assertThat(error.status().value()).isEqualTo(413));

        AnalysisMetadata valid = metadata("function-limit", source);
        ArrayList<AnalysisMetadata.FunctionMetadata> functions = new ArrayList<>();
        for (int index = 0; index < 3001; index++) {
            functions.add(new AnalysisMetadata.FunctionMetadata(null, null, "f" + index, null, null, null, 1, 1));
        }
        AnalysisMetadata tooMany = new AnalysisMetadata(
                valid.schemaVersion(), valid.analysisId(), valid.projectId(), valid.canonicalSha256(),
                valid.canonicalSizeBytes(), valid.projectStatus(), valid.engineName(), valid.engineVersion(), functions);

        assertThatThrownBy(() -> validator.validate(
                "function-limit", tooMany, source.getBytes(StandardCharsets.UTF_8)))
                .isInstanceOfSatisfying(ApiException.class,
                        error -> assertThat(error.code()).isEqualTo("too_many_functions"));
    }
}
