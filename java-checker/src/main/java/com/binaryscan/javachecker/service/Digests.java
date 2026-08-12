package com.binaryscan.javachecker.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import com.binaryscan.javachecker.api.AnalysisMetadata.FileMetadata;

public final class Digests {
    private Digests() {
    }

    public static String sha256(byte[] value) {
        MessageDigest digest = sha256Digest();
        return HexFormat.of().formatHex(digest.digest(value));
    }

    public static String sha256(byte[] value, int offset, int length) {
        MessageDigest digest = sha256Digest();
        digest.update(value, offset, length);
        return HexFormat.of().formatHex(digest.digest());
    }

    public static String inputSha256(Iterable<FileMetadata> files) {
        MessageDigest digest = sha256Digest();
        update(digest, CheckerConstants.REQUEST_SCHEMA + "\n");
        for (FileMetadata file : files) {
            update(digest, file.resultId());
            digest.update((byte) 0);
            update(digest, file.logicalPath());
            digest.update((byte) 0);
            update(digest, file.binaryName());
            digest.update((byte) 0);
            update(digest, Long.toString(file.lengthBytes()));
            digest.update((byte) 0);
            update(digest, file.sha256().toLowerCase(java.util.Locale.ROOT));
            digest.update((byte) '\n');
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void update(MessageDigest digest, String value) {
        digest.update(value.getBytes(StandardCharsets.UTF_8));
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("JDK does not provide SHA-256", impossible);
        }
    }
}
