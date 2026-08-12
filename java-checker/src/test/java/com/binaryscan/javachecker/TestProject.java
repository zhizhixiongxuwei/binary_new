package com.binaryscan.javachecker;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import com.binaryscan.javachecker.api.AnalysisMetadata;
import com.binaryscan.javachecker.service.Digests;

public final class TestProject {
    private TestProject() {
    }

    public static Request oneFile(String source) {
        return oneFile(source, "complete");
    }

    public static Request oneFile(String source, String projectStatus) {
        byte[] bundle = source.getBytes(StandardCharsets.UTF_8);
        String analysisId = UUID.randomUUID().toString();
        AnalysisMetadata.FileMetadata file = new AnalysisMetadata.FileMetadata(
                "result-1", "src/main/java/example/Rules.java", "example.Rules", "Rules.java",
                Digests.sha256(bundle), 0L, (long) bundle.length);
        AnalysisMetadata metadata = new AnalysisMetadata(
                "java-analysis-input-v1", analysisId, Digests.inputSha256(List.of(file)),
                Digests.sha256(bundle), "0".repeat(64), UUID.randomUUID().toString(),
                "java", projectStatus, List.of(file));
        return new Request(metadata, bundle);
    }

    public record Request(AnalysisMetadata metadata, byte[] bundle) {
    }
}
