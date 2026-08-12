package com.binaryscan.javachecker.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockPart;
import org.springframework.web.multipart.MultipartFile;

import com.binaryscan.javachecker.TestProject;
import com.binaryscan.javachecker.service.AnalysisCoordinator;
import com.binaryscan.javachecker.service.CheckerLimits;
import com.binaryscan.javachecker.service.SourceValidator;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.Part;

class AnalysisControllerAdmissionTest {
    @Test
    void concurrentPostsAreRejectedBeforeReadingPartsWhileAnAdmittedPostMaterializesSource() throws Exception {
        CheckerLimits limits = CheckerLimits.defaults();
        ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
        AnalysisCoordinator coordinator = new AnalysisCoordinator(mapper, limits);
        AnalysisController controller = new AnalysisController(
                mapper, new SourceValidator(limits), coordinator, limits);
        TestProject.Request request = TestProject.oneFile("class Admitted {}\n");

        MockPart admittedMetadata = new MockPart("metadata", mapper.writeValueAsBytes(request.metadata()));
        MultipartFile admittedSource = mock(MultipartFile.class);
        CountDownLatch sourceReadStarted = new CountDownLatch(1);
        CountDownLatch allowSourceRead = new CountDownLatch(1);
        when(admittedSource.getSize()).thenReturn((long) request.bundle().length);
        when(admittedSource.getBytes()).thenAnswer(invocation -> {
            sourceReadStarted.countDown();
            if (!allowSourceRead.await(5, TimeUnit.SECONDS)) {
                throw new IOException("test did not release admitted source read");
            }
            return request.bundle();
        });

        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<AnalysisResponse> admitted = executor.submit(() -> controller.analyze(
                request.metadata().analysisId(), admittedMetadata, admittedSource));
        try {
            assertThat(sourceReadStarted.await(5, TimeUnit.SECONDS)).isTrue();
            for (int index = 0; index < 3; index++) {
                Part rejectedMetadata = mock(Part.class);
                MultipartFile rejectedSource = mock(MultipartFile.class);

                ApiException error = assertThrows(ApiException.class, () -> controller.analyze(
                        UUID.randomUUID().toString(), rejectedMetadata, rejectedSource));

                assertThat(error.status()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
                assertThat(error.code()).isEqualTo("checker_busy");
                verifyNoInteractions(rejectedMetadata, rejectedSource);
            }
        } finally {
            allowSourceRead.countDown();
        }

        assertThat(admitted.get(10, TimeUnit.SECONDS).status()).isEqualTo("complete");
        executor.shutdownNow();
    }
}
