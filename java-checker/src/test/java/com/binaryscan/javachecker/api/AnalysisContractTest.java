package com.binaryscan.javachecker.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.mock.web.MockPart;
import org.springframework.test.web.servlet.MockMvc;

import com.binaryscan.javachecker.TestProject;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
class AnalysisContractTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper mapper;

    @Test
    void multipartRunsInIsolatedWorkerAndReturnsExactJsonContract() throws Exception {
        TestProject.Request request = TestProject.oneFile("""
                import java.security.MessageDigest;
                class Rules { void run() throws Exception { MessageDigest.getInstance("MD5"); } }
                """);

        mockMvc.perform(multipart("/internal/v1/analyses/{id}", request.metadata().analysisId())
                        .file(new MockMultipartFile("source", "source.bundle",
                                MediaType.APPLICATION_OCTET_STREAM_VALUE, request.bundle()))
                        .part(metadataPart(mapper.writeValueAsBytes(request.metadata()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.schema_version").value("java-analysis-response-v1"))
                .andExpect(jsonPath("$.analysis_id").value(request.metadata().analysisId()))
                .andExpect(jsonPath("$.status").value("complete"))
                .andExpect(jsonPath("$.identity.product").value("binaryscan-java-checker"))
                .andExpect(jsonPath("$.identity.version").value("0.1.0"))
                .andExpect(jsonPath("$.identity.ruleset").value("java-rules-v1"))
                .andExpect(jsonPath("$.input_sha256").value(request.metadata().inputSha256()))
                .andExpect(jsonPath("$.bundle_sha256").value(request.metadata().bundleSha256()))
                .andExpect(jsonPath("$.coverage.files_total").value(1))
                .andExpect(jsonPath("$.coverage.files_analyzed").value(1))
                .andExpect(jsonPath("$.coverage.files_parsed").value(1))
                .andExpect(jsonPath("$.coverage.files_recovered").value(0))
                .andExpect(jsonPath("$.coverage.files_failed").value(0))
                .andExpect(jsonPath("$.summary.findings_truncated").value(false))
                .andExpect(jsonPath("$.findings[0].rule_id").value("java-weak-message-digest"))
                .andExpect(jsonPath("$.findings[0].cwe").value("CWE-328"))
                .andExpect(jsonPath("$.findings[0].file.result_id").value("result-1"))
                .andExpect(jsonPath("$.findings[0].callable.kind").value("method"))
                .andExpect(jsonPath("$.findings[0].location.start_line").value(2))
                .andExpect(jsonPath("$.findings[0].snippet_start_line").isNumber());
    }

    @Test
    void rejectsUnknownFieldsAndInvalidUuid() throws Exception {
        TestProject.Request request = TestProject.oneFile("class Rules {}\n");
        String json = mapper.writeValueAsString(request.metadata());
        json = json.substring(0, json.length() - 1) + ",\"unexpected\":true}";

        mockMvc.perform(multipart("/internal/v1/analyses/{id}", request.metadata().analysisId())
                        .file(new MockMultipartFile("source", "", MediaType.APPLICATION_OCTET_STREAM_VALUE,
                                request.bundle()))
                        .part(metadataPart(json.getBytes(StandardCharsets.UTF_8))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_metadata_json"));

        mockMvc.perform(delete("/internal/v1/analyses/not-a-uuid"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_analysis_id"));
    }

    @Test
    void deleteIsIdempotentAndActuatorProbesAreExposed() throws Exception {
        String id = UUID.randomUUID().toString();
        mockMvc.perform(delete("/internal/v1/analyses/{id}", id)).andExpect(status().isNoContent());
        mockMvc.perform(delete("/internal/v1/analyses/{id}", id)).andExpect(status().isNoContent());
        mockMvc.perform(get("/actuator/health/liveness")).andExpect(status().isOk());
        mockMvc.perform(get("/actuator/health/readiness")).andExpect(status().isOk());
    }

    private static MockPart metadataPart(byte[] content) {
        MockPart part = new MockPart("metadata", content);
        part.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        return part;
    }
}
