package com.binaryscan.javachecker.api;

import java.io.IOException;
import java.io.InputStream;

import jakarta.servlet.http.Part;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.binaryscan.javachecker.service.AnalysisCoordinator;
import com.binaryscan.javachecker.service.CheckerLimits;
import com.binaryscan.javachecker.service.SourceValidator;
import com.binaryscan.javachecker.service.Utf8Text;
import com.binaryscan.javachecker.service.ValidatedRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
@RequestMapping("/internal/v1/analyses")
public class AnalysisController {
    private static final long MAX_METADATA_BYTES = 16L * 1024 * 1024;

    private final ObjectMapper mapper;
    private final SourceValidator validator;
    private final AnalysisCoordinator coordinator;
    private final CheckerLimits limits;

    public AnalysisController(
            ObjectMapper mapper,
            SourceValidator validator,
            AnalysisCoordinator coordinator,
            CheckerLimits limits) {
        this.mapper = mapper;
        this.validator = validator;
        this.coordinator = coordinator;
        this.limits = limits;
    }

    @PostMapping(path = "/{analysis_id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public AnalysisResponse analyze(
            @PathVariable("analysis_id") String analysisId,
            @RequestPart("metadata") Part metadataPart,
            @RequestPart("source") MultipartFile sourcePart) {
        try (AnalysisCoordinator.Admission admission = coordinator.reserve()) {
            requireMetadataSize(metadataPart.getSize());
            if (sourcePart.getSize() > limits.maxSourceBytes()) {
                throw new ApiException(HttpStatus.PAYLOAD_TOO_LARGE, "source_too_large",
                        "source part exceeds the 128 MiB limit");
            }
            try {
                AnalysisMetadata metadata = mapper.readValue(readMetadata(metadataPart), AnalysisMetadata.class);
                byte[] bundle = sourcePart.getBytes();
                ValidatedRequest request = validator.validateTransport(analysisId, metadata, bundle);
                return coordinator.analyze(admission, request, bundle);
            } catch (JsonProcessingException error) {
                throw new ApiException(HttpStatus.BAD_REQUEST, "invalid_metadata_json", firstLine(error.getMessage()));
            } catch (IOException error) {
                throw new ApiException(HttpStatus.BAD_REQUEST, "multipart_read_failed",
                        "multipart content could not be read");
            }
        }
    }

    @DeleteMapping("/{analysis_id}")
    public ResponseEntity<Void> cancel(@PathVariable("analysis_id") String analysisId) {
        coordinator.cancel(analysisId);
        return ResponseEntity.noContent().build();
    }

    private static byte[] readMetadata(Part part) throws IOException {
        try (InputStream input = part.getInputStream()) {
            byte[] bytes = input.readNBytes(Math.toIntExact(MAX_METADATA_BYTES + 1));
            requireMetadataSize(bytes.length);
            return bytes;
        }
    }

    private static void requireMetadataSize(long size) {
        if (size <= 0 || size > MAX_METADATA_BYTES) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "invalid_metadata_size",
                    "metadata part must contain at most 16 MiB");
        }
    }

    private static String firstLine(String message) {
        if (message == null || message.isBlank()) {
            return "metadata JSON is invalid";
        }
        int newline = message.indexOf('\n');
        String first = newline >= 0 ? message.substring(0, newline) : message;
        return Utf8Text.message(first);
    }
}
