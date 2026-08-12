package com.binaryscan.javachecker.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import com.binaryscan.javachecker.TestProject;
import com.binaryscan.javachecker.api.AnalysisResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

class AnalysisCoordinatorTest {
    @Test
    void timeoutForciblyTerminatesTheShortLivedWorker() {
        CheckerLimits limits = limits(Duration.ofMillis(1));
        TestProject.Request raw = TestProject.oneFile("class Timeout {}\n");
        ValidatedRequest request = new SourceValidator(limits)
                .validate(raw.metadata().analysisId(), raw.metadata(), raw.bundle());
        AnalysisCoordinator coordinator = new AnalysisCoordinator(new ObjectMapper().findAndRegisterModules(), limits);

        AnalysisResponse response = coordinator.analyze(request, raw.bundle());

        assertThat(response.status()).isEqualTo("failed");
        assertThat(response.diagnostics()).extracting(AnalysisResponse.Diagnostic::code)
                .containsExactly("analysis_timeout");
        assertThat(workerProcesses()).isZero();
    }

    @Test
    void deleteBeforeActiveRegistrationIsConsumedAsPendingCancellation() {
        CheckerLimits limits = limits(Duration.ofMinutes(1));
        TestProject.Request raw = TestProject.oneFile("class Pending {}\n");
        ValidatedRequest request = new SourceValidator(limits)
                .validateTransport(raw.metadata().analysisId(), raw.metadata(), raw.bundle());
        AnalysisCoordinator coordinator = new AnalysisCoordinator(new ObjectMapper().findAndRegisterModules(), limits);

        coordinator.cancel(raw.metadata().analysisId());
        coordinator.cancel(raw.metadata().analysisId());
        AnalysisResponse response = coordinator.analyze(request, raw.bundle());

        assertThat(response.status()).isEqualTo("cancelled");
        assertThat(response.diagnostics()).extracting(AnalysisResponse.Diagnostic::code)
                .containsExactly("analysis_cancelled");
        assertThat(workerProcesses()).isZero();
    }

    @Test
    void deleteHardCancelsAnActiveWorkerAndIsIdempotent() throws Exception {
        CheckerLimits limits = limits(Duration.ofMinutes(1));
        StringBuilder source = new StringBuilder("class Slow { void run() {\n");
        for (int i = 0; i < 80000; i++) {
            source.append("int value").append(i).append(" = ").append(i).append(";\n");
        }
        source.append("} }\n");
        TestProject.Request raw = TestProject.oneFile(source.toString());
        ValidatedRequest request = new SourceValidator(limits)
                .validate(raw.metadata().analysisId(), raw.metadata(), raw.bundle());
        AnalysisCoordinator coordinator = new AnalysisCoordinator(new ObjectMapper().findAndRegisterModules(), limits);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<AnalysisResponse> future = executor.submit(() -> coordinator.analyze(request, raw.bundle()));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (!future.isDone() && workerProcesses() == 0 && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }

            assertThat(workerProcesses()).isPositive();
            coordinator.cancel(raw.metadata().analysisId());
            coordinator.cancel(raw.metadata().analysisId());

            assertThat(future.get(10, TimeUnit.SECONDS).status()).isEqualTo("cancelled");
            assertThat(workerProcesses()).isZero();
        } finally {
            executor.shutdownNow();
        }
    }

    private static long workerProcesses() {
        return ProcessHandle.current().descendants()
                .filter(ProcessHandle::isAlive)
                .filter(process -> process.info().commandLine().orElse("").contains("javachecker.worker.WorkerMain"))
                .count();
    }

    private static CheckerLimits limits(Duration timeout) {
        return new CheckerLimits(
                128L * 1024 * 1024, 3000, 8L * 1024 * 1024, 10000, 1000, 1024,
                32L * 1024 * 1024, timeout, Duration.ofMillis(100));
    }
}
