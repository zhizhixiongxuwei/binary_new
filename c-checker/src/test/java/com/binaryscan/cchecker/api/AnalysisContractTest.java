package com.binaryscan.cchecker.api;

import static com.binaryscan.cchecker.TestRequests.metadata;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.mock.web.MockPart;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
class AnalysisContractTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void acceptsStableMultipartContractInEitherPartOrder() throws Exception {
        String analysisId = "analysis-1";
        String source = "int sample(char *p) {\n  gets(p);\n  return 0;\n}\n";
        MockMultipartFile sourcePart = new MockMultipartFile(
                "source", "source.c", MediaType.APPLICATION_OCTET_STREAM_VALUE,
                source.getBytes(StandardCharsets.UTF_8));
        MockPart metadataPart = metadataPart(
                "metadata.json", objectMapper.writeValueAsBytes(metadata(analysisId, source)));

        mockMvc.perform(multipart("/internal/v1/analyses/{id}", analysisId)
                        .file(sourcePart)
                        .part(metadataPart))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.schema_version").value("binaryscan-c-analysis-response/v1"))
                .andExpect(jsonPath("$.analysis_id").value(analysisId))
                .andExpect(jsonPath("$.status").value("succeeded"))
                .andExpect(jsonPath("$.checker.name").value("binaryscan-c-checker"))
                .andExpect(jsonPath("$.checker.version").value("0.1.0"))
                .andExpect(jsonPath("$.checker.ruleset_version").value("c-rules-v1"))
                .andExpect(jsonPath("$.coverage.total_functions").value(1))
                .andExpect(jsonPath("$.findings[0].cwe").value("CWE-242"))
                .andExpect(jsonPath("$.findings[0].rule_id").value("cwe-242-gets"))
                .andExpect(jsonPath("$.findings[0].severity").value("HIGH"))
                .andExpect(jsonPath("$.findings[0].function.result_id").value("result-1"))
                .andExpect(jsonPath("$.findings[0].location.start_line").value(2))
                .andExpect(jsonPath("$.findings[0].location.start_column").value(3))
                .andExpect(jsonPath("$.findings[0].confidence").doesNotExist())
                .andExpect(jsonPath("$.findings[0].remediation").doesNotExist());
    }

    @Test
    void acceptsJsonMetadataPartWithoutFilename() throws Exception {
        String analysisId = "analysis-no-metadata-filename";
        String source = "int sample(void) {\n  return 0;\n}\n";

        mockMvc.perform(multipart("/internal/v1/analyses/{id}", analysisId)
                        .part(metadataPart(
                                null, objectMapper.writeValueAsBytes(metadata(analysisId, source))))
                        .file(new MockMultipartFile(
                                "source", "source.c", MediaType.APPLICATION_OCTET_STREAM_VALUE,
                                source.getBytes(StandardCharsets.UTF_8))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.analysis_id").value(analysisId))
                .andExpect(jsonPath("$.status").value("succeeded"))
                .andExpect(jsonPath("$.coverage.total_functions").value(1));
    }

    @Test
    void rejectsUnknownMetadataFields() throws Exception {
        String source = "int sample(void) { return 0; }\n";
        String json = objectMapper.writeValueAsString(metadata("analysis-unknown", source));
        json = json.substring(0, json.length() - 1) + ",\"unexpected\":true}";

        mockMvc.perform(multipart("/internal/v1/analyses/analysis-unknown")
                        .part(metadataPart(null, json.getBytes(StandardCharsets.UTF_8)))
                        .file(new MockMultipartFile("source", "", MediaType.APPLICATION_OCTET_STREAM_VALUE,
                                source.getBytes(StandardCharsets.UTF_8))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_metadata_json"));
    }

    @Test
    void acceptsWorstCaseContractMetadataAtTheTransportBoundary() throws Exception {
        byte[] metadataBytes = new byte[12 * 1024 * 1024];

        mockMvc.perform(multipart("/internal/v1/analyses/analysis-large-metadata")
                        .part(metadataPart(null, metadataBytes))
                        .file(new MockMultipartFile("source", "", MediaType.APPLICATION_OCTET_STREAM_VALUE,
                                "int sample(void) { return 0; }\n".getBytes(StandardCharsets.UTF_8))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_metadata_json"));
    }

    @Test
    void deleteIsIdempotentAndHealthProbesAreAvailable() throws Exception {
        mockMvc.perform(delete("/internal/v1/analyses/not-running"))
                .andExpect(status().isNoContent());
        mockMvc.perform(delete("/internal/v1/analyses/not-running"))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/actuator/health/liveness"))
                .andExpect(status().isOk());
        mockMvc.perform(get("/actuator/health/readiness"))
                .andExpect(status().isOk());
    }

    private static MockPart metadataPart(String filename, byte[] content) {
        MockPart part = filename == null
                ? new MockPart("metadata", content)
                : new MockPart("metadata", filename, content);
        part.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        return part;
    }
}
