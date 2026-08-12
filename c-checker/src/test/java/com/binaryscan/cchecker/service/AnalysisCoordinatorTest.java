package com.binaryscan.cchecker.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import com.binaryscan.cchecker.api.AnalysisMetadata;
import com.binaryscan.cchecker.api.AnalysisResponse;
import com.binaryscan.cchecker.api.ApiException;
import com.binaryscan.cchecker.service.AnalysisRunContext.AnalysisStoppedException;

class AnalysisCoordinatorTest {
    @Test
    void rejectsConcurrentWorkAndCooperativelyCancelsTheActiveAnalysis() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        AnalysisEngine blockingEngine = (request, context) -> {
            started.countDown();
            try {
                while (true) {
                    context.checkpoint();
                    Thread.onSpinWait();
                }
            } catch (AnalysisStoppedException stopped) {
                return response(request.metadata().analysisId(), "cancelled");
            }
        };
        CheckerLimits limits = new CheckerLimits(
                1024, 3000, 10000, 1000, 1024, Duration.ofMinutes(1));
        AnalysisCoordinator coordinator = new AnalysisCoordinator(blockingEngine, limits);
        ValidatedRequest activeRequest = request("active");
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<AnalysisResponse> active = executor.submit(() -> coordinator.analyze(activeRequest));
            assertThat(started.await(2, TimeUnit.SECONDS)).isTrue();

            assertThatThrownBy(() -> coordinator.analyze(request("second")))
                    .isInstanceOfSatisfying(ApiException.class, error -> {
                        assertThat(error.status().value()).isEqualTo(429);
                        assertThat(error.code()).isEqualTo("analysis_busy");
                    });

            coordinator.cancel("different-id");
            assertThat(active.isDone()).isFalse();
            coordinator.cancel("active");
            assertThat(active.get(2, TimeUnit.SECONDS).status()).isEqualTo("cancelled");
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void appliesCancellationThatArrivesBeforeTheAnalysisIsRegistered() {
        AnalysisEngine cancellableEngine = (request, context) -> {
            try {
                context.checkpoint();
                return response(request.metadata().analysisId(), "succeeded");
            } catch (AnalysisStoppedException stopped) {
                return response(request.metadata().analysisId(), "cancelled");
            }
        };
        CheckerLimits limits = new CheckerLimits(
                1024, 3000, 10000, 1000, 1024, Duration.ofMinutes(1));
        AnalysisCoordinator coordinator = new AnalysisCoordinator(cancellableEngine, limits);

        coordinator.cancel("pending");
        coordinator.cancel("pending");

        assertThat(coordinator.analyze(request("pending")).status()).isEqualTo("cancelled");
    }

    private static ValidatedRequest request(String id) {
        AnalysisMetadata metadata = new AnalysisMetadata(
                "binaryscan-c-analysis-request/v1", id, "project", "0".repeat(64), 0L, "complete",
                "ghidra", "12.1.2", List.of());
        return new ValidatedRequest(metadata, List.of());
    }

    private static AnalysisResponse response(String id, String status) {
        return new AnalysisResponse(
                "binaryscan-c-analysis-response/v1",
                id,
                status,
                new AnalysisResponse.Checker("binaryscan-c-checker", "0.1.0", "c-rules-v1"),
                new AnalysisResponse.Coverage(0, 0, 0),
                new AnalysisResponse.Summary(0, 0, false, false),
                List.of(),
                List.of());
    }
}
