package com.binaryscan.javachecker.service;

import static com.binaryscan.javachecker.service.CheckerConstants.REQUEST_SCHEMA;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import com.binaryscan.javachecker.api.AnalysisMetadata;
import com.binaryscan.javachecker.api.AnalysisMetadata.FileMetadata;
import com.binaryscan.javachecker.api.ApiException;

@Component
public class SourceValidator {
    private static final Pattern SHA256 = Pattern.compile("[0-9a-fA-F]{64}");
    private static final Comparator<String> UTF8_ORDER = (left, right) ->
            Arrays.compareUnsigned(left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8));

    private final CheckerLimits limits;

    public SourceValidator(CheckerLimits limits) {
        this.limits = limits;
    }

    public ValidatedRequest validate(String pathAnalysisId, AnalysisMetadata metadata, byte[] bundle) {
        return validate(pathAnalysisId, metadata, bundle, true);
    }

    public ValidatedRequest validateTransport(String pathAnalysisId, AnalysisMetadata metadata, byte[] bundle) {
        return validate(pathAnalysisId, metadata, bundle, false);
    }

    private ValidatedRequest validate(
            String pathAnalysisId, AnalysisMetadata metadata, byte[] bundle, boolean retainSource) {
        requireValidUuid(pathAnalysisId);
        require(metadata != null, "metadata_missing", "metadata part is required");
        require(REQUEST_SCHEMA.equals(metadata.schemaVersion()), "unsupported_schema",
                "schema_version must be " + REQUEST_SCHEMA);
        require(pathAnalysisId.equals(metadata.analysisId()), "analysis_id_mismatch",
                "metadata analysis_id must match the request path");

        require(bundle != null && bundle.length > 0, "source_empty", "source bundle must not be empty");
        require(bundle.length <= limits.maxSourceBytes(), "source_too_large",
                "source bundle exceeds the 128 MiB limit", HttpStatus.PAYLOAD_TOO_LARGE);
        requireSha(metadata.inputSha256(), "input_sha256");
        requireSha(metadata.bundleSha256(), "bundle_sha256");
        if (metadata.sourceManifestSha256() != null) {
            requireSha(metadata.sourceManifestSha256(), "source_manifest_sha256");
        }
        require(Digests.sha256(bundle).equals(metadata.bundleSha256().toLowerCase(Locale.ROOT)),
                "bundle_sha256_mismatch", "bundle_sha256 does not match the source part",
                HttpStatus.UNPROCESSABLE_ENTITY);

        requireCanonicalUuid(metadata.projectId(), "project_id");
        String language = metadata.language();
        require("java".equals(language) || "mixed".equals(language), "invalid_language",
                "language must be java or mixed");
        String projectStatus = metadata.projectStatus();
        require("complete".equals(projectStatus) || "partial".equals(projectStatus),
                "invalid_project_status", "project_status must be complete or partial");

        List<FileMetadata> entries = metadata.files();
        require(entries != null && !entries.isEmpty(), "files_missing", "files must be a non-empty array");
        require(entries.size() <= limits.maxFiles(), "too_many_files",
                "files exceeds the limit of " + limits.maxFiles());

        List<SourceFile> files = new ArrayList<>(entries.size());
        Set<String> resultIds = new HashSet<>();
        Set<String> logicalPaths = new HashSet<>();
        long expectedOffset = 0;
        String priorPath = null;
        for (int index = 0; index < entries.size(); index++) {
            FileMetadata entry = entries.get(index);
            String prefix = "files[" + index + "]";
            require(entry != null, "invalid_file", prefix + " must be an object");
            requireBoundedUtf8(entry.resultId(), 1, 128, prefix + ".result_id");
            require(resultIds.add(entry.resultId()), "duplicate_result_id",
                    prefix + ".result_id is duplicated");
            validateLogicalPath(entry.logicalPath(), prefix);
            require(logicalPaths.add(entry.logicalPath()), "duplicate_logical_path",
                    prefix + ".logical_path is duplicated");
            if (priorPath != null) {
                require(UTF8_ORDER.compare(priorPath, entry.logicalPath()) < 0, "files_not_sorted",
                        "files must be sorted by logical_path UTF-8 bytes");
            }
            priorPath = entry.logicalPath();

            requireBoundedUtf8(entry.binaryName(), 1, 1024, prefix + ".binary_name");
            if (entry.displayName() != null) {
                requireBoundedUtf8(entry.displayName(), 1, 1024, prefix + ".display_name");
            }
            requireSha(entry.sha256(), prefix + ".sha256");
            require(entry.offsetBytes() != null && entry.offsetBytes() >= 0, "invalid_file_range",
                    prefix + ".offset_bytes must be non-negative");
            require(entry.lengthBytes() != null && entry.lengthBytes() > 0, "invalid_file_range",
                    prefix + ".length_bytes must be positive");
            require(entry.offsetBytes() == expectedOffset, "non_contiguous_file_ranges",
                    prefix + ".offset_bytes must immediately follow the preceding file");

            long end;
            try {
                end = Math.addExact(entry.offsetBytes(), entry.lengthBytes());
            } catch (ArithmeticException overflow) {
                end = Long.MAX_VALUE;
            }
            require(end <= bundle.length && entry.lengthBytes() <= Integer.MAX_VALUE, "invalid_file_range",
                    prefix + " byte range exceeds the source bundle");
            int offset = Math.toIntExact(entry.offsetBytes());
            int length = Math.toIntExact(entry.lengthBytes());
            require(Digests.sha256(bundle, offset, length).equals(entry.sha256().toLowerCase(Locale.ROOT)),
                    "file_sha256_mismatch", prefix + ".sha256 does not match its byte range",
                    HttpStatus.UNPROCESSABLE_ENTITY);
            if (retainSource) {
                files.add(new SourceFile(entry, length, decodeUtf8(bundle, offset, length, prefix)));
            } else {
                validateUtf8(bundle, offset, length, prefix);
                files.add(new SourceFile(entry, length, ""));
            }
            expectedOffset = end;
        }
        require(expectedOffset == bundle.length, "incomplete_file_ranges",
                "file ranges must cover the complete source bundle");
        require(Digests.inputSha256(entries).equals(metadata.inputSha256().toLowerCase(Locale.ROOT)),
                "input_sha256_mismatch", "input_sha256 does not match the canonical file identity framing",
                HttpStatus.UNPROCESSABLE_ENTITY);
        return new ValidatedRequest(metadata, List.copyOf(files));
    }

    public static void requireValidUuid(String analysisId) {
        requireCanonicalUuid(analysisId, "analysis_id");
    }

    private static void requireCanonicalUuid(String value, String field) {
        try {
            require(value != null && value.equals(UUID.fromString(value).toString()),
                    "invalid_" + field, field + " must be a canonical UUID");
        } catch (IllegalArgumentException error) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "invalid_" + field,
                    field + " must be a canonical UUID");
        }
    }

    private static void validateLogicalPath(String path, String prefix) {
        requireBoundedUtf8(path, 1, 4096, prefix + ".logical_path");
        require(path.endsWith(".java"), "invalid_java_path", prefix + ".logical_path must end in .java");
        require(!path.startsWith("/") && !path.startsWith("\\") && !path.contains("\\"),
                "unsafe_logical_path", prefix + ".logical_path must be a relative slash-separated path");
        require(path.indexOf('\0') < 0, "unsafe_logical_path", prefix + ".logical_path contains NUL");
        for (String segment : path.split("/", -1)) {
            require(!segment.isEmpty() && !".".equals(segment) && !"..".equals(segment),
                    "unsafe_logical_path", prefix + ".logical_path contains an unsafe segment");
        }
    }

    private static String decodeUtf8(byte[] bytes, int offset, int length, String prefix) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes, offset, length).slice())
                    .toString();
        } catch (CharacterCodingException error) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "invalid_source_utf8",
                    prefix + " is not valid UTF-8");
        }
    }

    private static void validateUtf8(byte[] bytes, int offset, int length, String prefix) {
        var decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        ByteBuffer input = ByteBuffer.wrap(bytes, offset, length).slice();
        CharBuffer output = CharBuffer.allocate(8192);
        try {
            while (true) {
                var result = decoder.decode(input, output, true);
                if (result.isError()) {
                    result.throwException();
                }
                output.clear();
                if (result.isUnderflow()) {
                    break;
                }
            }
            var flushed = decoder.flush(output);
            if (flushed.isError()) {
                flushed.throwException();
            }
        } catch (CharacterCodingException error) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "invalid_source_utf8",
                    prefix + " is not valid UTF-8");
        }
    }

    private static void requireSha(String value, String field) {
        require(value != null && SHA256.matcher(value).matches(), "invalid_sha256",
                field + " must contain 64 hexadecimal characters");
    }

    private static void requireBounded(String value, int min, int max, String field) {
        require(value != null && value.length() >= min && value.length() <= max,
                "invalid_metadata_field", field + " length must be between " + min + " and " + max);
    }

    private static void requireBoundedUtf8(String value, int min, int maxBytes, String field) {
        require(value != null && value.length() >= min
                        && isWellFormedUnicode(value)
                        && value.getBytes(StandardCharsets.UTF_8).length <= maxBytes,
                "invalid_metadata_field", field + " must contain between " + min + " characters and "
                        + maxBytes + " UTF-8 bytes");
    }

    private static boolean isWellFormedUnicode(String value) {
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (Character.isHighSurrogate(current)) {
                if (index + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(index + 1))) {
                    return false;
                }
                index++;
            } else if (Character.isLowSurrogate(current)) {
                return false;
            }
        }
        return true;
    }

    private static void require(boolean condition, String code, String message) {
        require(condition, code, message, HttpStatus.BAD_REQUEST);
    }

    private static void require(boolean condition, String code, String message, HttpStatus status) {
        if (!condition) {
            throw new ApiException(status, code, message);
        }
    }
}
