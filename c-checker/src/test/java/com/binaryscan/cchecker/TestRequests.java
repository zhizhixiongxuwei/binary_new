package com.binaryscan.cchecker;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

import com.binaryscan.cchecker.api.AnalysisMetadata;

public final class TestRequests {
    private TestRequests() {
    }

    public static AnalysisMetadata metadata(String analysisId, String source) {
        byte[] bytes = source.getBytes(StandardCharsets.UTF_8);
        int endLine = Math.max(1, (int) source.lines().count());
        AnalysisMetadata.FunctionMetadata function = new AnalysisMetadata.FunctionMetadata(
                "result-1",
                "0x1000",
                "sample",
                sha256(bytes),
                0L,
                (long) bytes.length,
                1,
                endLine);
        return new AnalysisMetadata(
                "binaryscan-c-analysis-request/v1",
                analysisId,
                "project-1",
                sha256(bytes),
                (long) bytes.length,
                "complete",
                "ghidra",
                "12.1.2",
                List.of(function));
    }

    public static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }
}
