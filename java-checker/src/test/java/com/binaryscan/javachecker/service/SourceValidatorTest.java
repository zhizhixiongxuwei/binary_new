package com.binaryscan.javachecker.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.binaryscan.javachecker.TestProject;
import com.binaryscan.javachecker.api.AnalysisMetadata;
import com.binaryscan.javachecker.api.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;

class SourceValidatorTest {
    private final CheckerLimits limits = CheckerLimits.defaults();
    private final SourceValidator validator = new SourceValidator(limits);

    @Test
    void validatesCanonicalIdentityContiguousRangesHashesAndUtf8() {
        TestProject.Request request = TestProject.oneFile("package example; class Rules {}\n");

        ValidatedRequest validated = validator.validate(
                request.metadata().analysisId(), request.metadata(), request.bundle());

        assertThat(validated.files()).hasSize(1);
        assertThat(validated.files().get(0).source()).contains("class Rules");
        assertThat(validated.files().get(0).identity().logicalPath())
                .isEqualTo("src/main/java/example/Rules.java");
    }

    @Test
    void acceptsBackendOffsetAndLengthAliases() throws Exception {
        TestProject.Request request = TestProject.oneFile("class Rules {}\n");
        String json = new ObjectMapper().writeValueAsString(request.metadata())
                .replace("offset_bytes", "offset")
                .replace("length_bytes", "length");

        AnalysisMetadata decoded = new ObjectMapper().readValue(json, AnalysisMetadata.class);

        assertThat(decoded.files().get(0).offsetBytes()).isZero();
        assertThat(decoded.files().get(0).lengthBytes()).isEqualTo(request.bundle().length);
    }

    @Test
    void rejectsGapAndTrailingUnclaimedBytes() {
        TestProject.Request request = TestProject.oneFile("class Rules {}\n");
        AnalysisMetadata.FileMetadata original = request.metadata().files().get(0);
        AnalysisMetadata.FileMetadata shifted = new AnalysisMetadata.FileMetadata(
                original.resultId(), original.logicalPath(), original.binaryName(), original.displayName(),
                original.sha256(), 1L, original.lengthBytes());
        AnalysisMetadata changed = replaceFiles(request.metadata(), List.of(shifted));

        assertThatThrownBy(() -> validator.validate(changed.analysisId(), changed, request.bundle()))
                .isInstanceOf(ApiException.class)
                .extracting(error -> ((ApiException) error).code())
                .isEqualTo("non_contiguous_file_ranges");
    }

    @Test
    void rejectsPerFileDigestMismatchAndMalformedUtf8() {
        TestProject.Request request = TestProject.oneFile("class Rules {}\n");
        AnalysisMetadata.FileMetadata original = request.metadata().files().get(0);
        AnalysisMetadata.FileMetadata wrongHash = new AnalysisMetadata.FileMetadata(
                original.resultId(), original.logicalPath(), original.binaryName(), original.displayName(),
                "f".repeat(64), original.offsetBytes(), original.lengthBytes());
        AnalysisMetadata hashMetadata = replaceFiles(request.metadata(), List.of(wrongHash));
        assertThatThrownBy(() -> validator.validate(hashMetadata.analysisId(), hashMetadata, request.bundle()))
                .isInstanceOf(ApiException.class);

        byte[] invalid = {(byte) 0xc3, (byte) 0x28};
        AnalysisMetadata.FileMetadata invalidFile = new AnalysisMetadata.FileMetadata(
                "result-1", original.logicalPath(), original.binaryName(), original.displayName(),
                Digests.sha256(invalid), 0L, 2L);
        AnalysisMetadata invalidMetadata = new AnalysisMetadata(
                "java-analysis-input-v1", request.metadata().analysisId(),
                Digests.inputSha256(List.of(invalidFile)), Digests.sha256(invalid), "0".repeat(64),
                request.metadata().projectId(), "java", "complete", List.of(invalidFile));
        assertThatThrownBy(() -> validator.validate(invalidMetadata.analysisId(), invalidMetadata, invalid))
                .isInstanceOf(ApiException.class)
                .extracting(error -> ((ApiException) error).code())
                .isEqualTo("invalid_source_utf8");
    }

    @Test
    void inputDigestUsesDocumentedNulDelimitedFraming() {
        byte[] body = "class A {}\n".getBytes(StandardCharsets.UTF_8);
        AnalysisMetadata.FileMetadata file = new AnalysisMetadata.FileMetadata(
                "r", "A.java", "A", null, Digests.sha256(body), 0L, (long) body.length);
        String framing = "java-analysis-input-v1\n"
                + "r\0A.java\0A\0" + body.length + "\0" + file.sha256() + "\n";

        assertThat(Digests.inputSha256(List.of(file)))
                .isEqualTo(Digests.sha256(framing.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void requiresProjectUuidLanguageAndProjectStatus() {
        TestProject.Request request = TestProject.oneFile("class Rules {}\n");
        AnalysisMetadata missing = new AnalysisMetadata(
                request.metadata().schemaVersion(), request.metadata().analysisId(),
                request.metadata().inputSha256(), request.metadata().bundleSha256(),
                request.metadata().sourceManifestSha256(), null, null, null, request.metadata().files());

        assertThatThrownBy(() -> validator.validate(missing.analysisId(), missing, request.bundle()))
                .isInstanceOf(ApiException.class)
                .extracting(error -> ((ApiException) error).code())
                .isEqualTo("invalid_project_id");
    }

    @Test
    void transportValidationAt128MiBDoesNotRetainPerFileCopiesOrDecodedText() {
        byte[] bundle = new byte[Math.toIntExact(limits.maxSourceBytes())];
        String hash = Digests.sha256(bundle);
        AnalysisMetadata.FileMetadata file = new AnalysisMetadata.FileMetadata(
                "result-max", "src/main/java/example/Maximum.java", "example.Maximum", "Maximum.java",
                hash, 0L, (long) bundle.length);
        AnalysisMetadata metadata = new AnalysisMetadata(
                "java-analysis-input-v1", UUID.randomUUID().toString(), Digests.inputSha256(List.of(file)),
                hash, "0".repeat(64), UUID.randomUUID().toString(), "java", "complete", List.of(file));

        ValidatedRequest request = validator.validateTransport(metadata.analysisId(), metadata, bundle);

        assertThat(request.files()).singleElement().satisfies(source -> {
            assertThat(source.byteLength()).isEqualTo(bundle.length);
            assertThat(source.source()).isEmpty();
        });
    }

    private static AnalysisMetadata replaceFiles(
            AnalysisMetadata metadata, List<AnalysisMetadata.FileMetadata> files) {
        return new AnalysisMetadata(
                metadata.schemaVersion(), metadata.analysisId(), metadata.inputSha256(),
                metadata.bundleSha256(), metadata.sourceManifestSha256(), metadata.projectId(),
                metadata.language(), metadata.projectStatus(), files);
    }
}
