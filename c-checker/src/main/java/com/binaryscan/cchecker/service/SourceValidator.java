package com.binaryscan.cchecker.service;

import static com.binaryscan.cchecker.service.CheckerConstants.REQUEST_SCHEMA;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import com.binaryscan.cchecker.api.AnalysisMetadata;
import com.binaryscan.cchecker.api.AnalysisMetadata.FunctionMetadata;
import com.binaryscan.cchecker.api.AnalysisResponse;
import com.binaryscan.cchecker.api.ApiException;

@Component
public class SourceValidator {
    private static final Pattern SHA256 = Pattern.compile("[0-9a-fA-F]{64}");
    private static final Pattern ANALYSIS_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");

    private final CheckerLimits limits;

    public SourceValidator(CheckerLimits limits) {
        this.limits = limits;
    }

    public ValidatedRequest validate(String pathAnalysisId, AnalysisMetadata metadata, byte[] source) {
        require(source != null && source.length <= limits.maxSourceBytes(), "source_too_large",
                "source part exceeds the configured byte limit", HttpStatus.PAYLOAD_TOO_LARGE);
        require(source.length > 0, "source_empty", "source part must not be empty");
        if (metadata == null) {
            badRequest("metadata_missing", "metadata part is required");
        }
        require(REQUEST_SCHEMA.equals(metadata.schemaVersion()), "unsupported_schema",
                "schema_version must be " + REQUEST_SCHEMA);
        require(matchesAnalysisId(pathAnalysisId), "invalid_analysis_id", "analysis_id path value is invalid");
        require(pathAnalysisId.equals(metadata.analysisId()), "analysis_id_mismatch",
                "metadata analysis_id must match the request path");
        requireBounded(metadata.projectId(), 1, 128, "project_id");
        require(metadata.canonicalSizeBytes() != null && metadata.canonicalSizeBytes() > 0,
                "invalid_canonical_size", "canonical_size_bytes must be a positive integer");
        require(metadata.canonicalSizeBytes() == source.length, "canonical_size_mismatch",
                "canonical_size_bytes does not match the source part", HttpStatus.UNPROCESSABLE_ENTITY);
        requireSha(metadata.canonicalSha256(), "canonical_sha256");
        String sourceHash = sha256(source);
        require(sourceHash.equals(metadata.canonicalSha256().toLowerCase(Locale.ROOT)),
                "canonical_sha256_mismatch", "canonical_sha256 does not match the source part",
                HttpStatus.UNPROCESSABLE_ENTITY);
        require("complete".equals(metadata.projectStatus()) || "partial".equals(metadata.projectStatus()),
                "invalid_project_status", "project_status must be complete or partial");
        requireBounded(metadata.engineName(), 1, 128, "engine_name");
        requireBounded(metadata.engineVersion(), 1, 128, "engine_version");

        List<FunctionMetadata> requested = metadata.functions();
        require(requested != null && !requested.isEmpty(), "functions_missing",
                "functions must be a non-empty array");
        require(requested.size() <= limits.maxFunctions(), "too_many_functions",
                "functions exceeds the limit of " + limits.maxFunctions());

        LineIndex lineIndex = lineIndex(source, requested);
        List<FunctionSlice> functions = new ArrayList<>(requested.size());
        Set<String> resultIds = new HashSet<>();
        NavigableMap<Long, Long> claimedRanges = new TreeMap<>();
        for (int index = 0; index < requested.size(); index++) {
            FunctionMetadata function = requested.get(index);
            require(function != null, "invalid_function", "functions[" + index + "] must be an object");
            functions.add(validateFunction(function, index, source, lineIndex, resultIds, claimedRanges));
        }
        return new ValidatedRequest(metadata, List.copyOf(functions));
    }

    private FunctionSlice validateFunction(
            FunctionMetadata function,
            int index,
            byte[] source,
            LineIndex lineIndex,
            Set<String> resultIds,
            NavigableMap<Long, Long> claimedRanges) {
        String prefix = "functions[" + index + "]";
        requireBoundedUtf8(function.name(), 1, 512, prefix + ".name");
        require(function.startLine() != null && function.startLine() >= 1,
                "invalid_function_range", prefix + ".start_line must be positive");
        require(function.endLine() != null && function.endLine() >= function.startLine(),
                "invalid_function_range", prefix + ".end_line must not precede start_line");
        require(function.endLine() <= lineIndex.totalLines(), "invalid_function_range",
                prefix + ".end_line exceeds the source line count");

        boolean compatibilityRange = function.resultId() == null
                && function.address() == null
                && function.sha256() == null
                && function.offsetBytes() == null
                && function.lengthBytes() == null;

        long offset;
        long length;
        String resultId;
        String address;
        if (compatibilityRange) {
            offset = lineIndex.offset(function.startLine());
            length = lineEndExclusive(function.endLine(), source.length, lineIndex) - offset;
            resultId = "";
            address = "";
        } else {
            requireBounded(function.resultId(), 1, 128, prefix + ".result_id");
            requireBounded(function.address(), 1, 128, prefix + ".address");
            requireSha(function.sha256(), prefix + ".sha256");
            require(function.offsetBytes() != null && function.offsetBytes() >= 0,
                    "invalid_function_range", prefix + ".offset_bytes must be non-negative");
            require(function.lengthBytes() != null && function.lengthBytes() > 0,
                    "invalid_function_range", prefix + ".length_bytes must be positive");
            offset = function.offsetBytes();
            length = function.lengthBytes();
            resultId = function.resultId();
            address = function.address();
            require(resultIds.add(resultId), "duplicate_function_result_id",
                    prefix + ".result_id is duplicated");
        }

        require(length > 0 && length <= Integer.MAX_VALUE, "invalid_function_range",
                prefix + " selects an empty or unsupported function body");
        long end;
        try {
            end = Math.addExact(offset, length);
        } catch (ArithmeticException overflow) {
            end = Long.MAX_VALUE;
        }
        require(end <= source.length, "invalid_function_range", prefix + " byte range exceeds the source part");
        claimRange(claimedRanges, offset, end);

        if (!compatibilityRange) {
            int expectedOffset = lineIndex.offset(function.startLine());
            int derivedEnd = function.startLine() + lineSpan(source, (int) offset, (int) length) - 1;
            require(offset == expectedOffset && derivedEnd == function.endLine(),
                    "function_line_range_mismatch", prefix + " byte and line ranges do not describe the same text",
                    HttpStatus.UNPROCESSABLE_ENTITY);
        }

        if (!compatibilityRange) {
            require(sha256(source, (int) offset, (int) length).equals(function.sha256().toLowerCase(Locale.ROOT)),
                    "function_sha256_mismatch", prefix + ".sha256 does not match its byte range",
                    HttpStatus.UNPROCESSABLE_ENTITY);
        }

        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(source, (int) offset, (int) length))
                    .toString();
        } catch (CharacterCodingException error) {
            throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "invalid_source_encoding",
                    prefix + " is not valid UTF-8");
        }

        AnalysisResponse.Function identity = new AnalysisResponse.Function(resultId, address, function.name());
        return new FunctionSlice(identity, function.startLine(), function.endLine(), offset, (int) length, text);
    }

    private static int lineEndExclusive(int endLine, int sourceLength, LineIndex lineIndex) {
        return endLine < lineIndex.totalLines() ? lineIndex.offset(endLine + 1) : sourceLength;
    }

    private static void claimRange(NavigableMap<Long, Long> claimedRanges, long start, long end) {
        Map.Entry<Long, Long> previous = claimedRanges.floorEntry(start);
        require(previous == null || previous.getValue() <= start, "overlapping_function_ranges",
                "function byte ranges must not overlap");
        Map.Entry<Long, Long> next = claimedRanges.ceilingEntry(start);
        require(next == null || end <= next.getKey(), "overlapping_function_ranges",
                "function byte ranges must not overlap");
        claimedRanges.put(start, end);
    }

    private static LineIndex lineIndex(byte[] source, List<FunctionMetadata> functions) {
        Set<Integer> neededLines = new HashSet<>();
        for (FunctionMetadata function : functions) {
            if (function == null) {
                continue;
            }
            if (function.startLine() != null && function.startLine() > 0) {
                neededLines.add(function.startLine());
            }
            if (function.endLine() != null && function.endLine() > 0
                    && function.endLine() < Integer.MAX_VALUE) {
                neededLines.add(function.endLine() + 1);
            }
        }
        Map<Integer, Integer> offsets = new HashMap<>(Math.max(16, neededLines.size() * 2));
        int line = 1;
        if (neededLines.contains(line)) {
            offsets.put(line, 0);
        }
        for (int index = 0; index < source.length; index++) {
            if (source[index] == '\n') {
                line++;
                if (neededLines.contains(line)) {
                    offsets.put(line, index + 1);
                }
            }
        }
        return new LineIndex(line, Map.copyOf(offsets));
    }

    private static int lineSpan(byte[] source, int offset, int length) {
        int newlines = 0;
        int end = offset + length;
        for (int index = offset; index < end; index++) {
            if (source[index] == '\n') {
                newlines++;
            }
        }
        return newlines + (source[end - 1] == '\n' ? 0 : 1);
    }

    private static boolean matchesAnalysisId(String value) {
        return value != null && ANALYSIS_ID.matcher(value).matches();
    }

    private static void requireSha(String value, String field) {
        require(value != null && SHA256.matcher(value).matches(), "invalid_sha256",
                field + " must contain exactly 64 hexadecimal characters");
    }

    private static void requireBounded(String value, int minimum, int maximum, String field) {
        require(value != null && value.length() >= minimum && value.length() <= maximum,
                "invalid_field", field + " length must be between " + minimum + " and " + maximum);
    }

    private static void requireBoundedUtf8(String value, int minimum, int maximum, String field) {
        int length = value == null ? -1 : value.getBytes(StandardCharsets.UTF_8).length;
        require(length >= minimum && length <= maximum, "invalid_field",
                field + " UTF-8 length must be between " + minimum + " and " + maximum + " bytes");
    }

    private static String sha256(byte[] content) {
        return sha256(content, 0, content.length);
    }

    private static String sha256(byte[] content, int offset, int length) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(content, offset, length);
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static void require(boolean condition, String code, String message) {
        require(condition, code, message, HttpStatus.BAD_REQUEST);
    }

    private static void require(boolean condition, String code, String message, HttpStatus status) {
        if (!condition) {
            throw new ApiException(status, code, message);
        }
    }

    private static void badRequest(String code, String message) {
        throw new ApiException(HttpStatus.BAD_REQUEST, code, message);
    }

    private record LineIndex(int totalLines, Map<Integer, Integer> offsets) {
        private int offset(int line) {
            Integer offset = offsets.get(line);
            if (offset == null) {
                throw new IllegalStateException("line offset was not indexed");
            }
            return offset;
        }
    }
}
