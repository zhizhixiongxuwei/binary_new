package com.binaryscan.javachecker.service;

import static com.binaryscan.javachecker.service.CheckerConstants.PRODUCT;
import static com.binaryscan.javachecker.service.CheckerConstants.RESPONSE_SCHEMA;
import static com.binaryscan.javachecker.service.CheckerConstants.RULESET;
import static com.binaryscan.javachecker.service.CheckerConstants.VERSION;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.boot.system.ApplicationHome;

import com.binaryscan.javachecker.api.AnalysisResponse;
import com.binaryscan.javachecker.api.ApiException;
import com.binaryscan.javachecker.worker.WorkerMain;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class AnalysisCoordinator {
    private static final int MAX_PENDING_CANCELLATIONS = 4096;
    private static final Set<String> STATUSES = Set.of("complete", "partial", "failed", "cancelled");

    private final ObjectMapper mapper;
    private final CheckerLimits limits;
    private final Semaphore analysisSlot = new Semaphore(1, true);
    private final ConcurrentHashMap<String, ActiveRun> active = new ConcurrentHashMap<>();
    private final Map<String, Long> pendingCancellations = new LinkedHashMap<>();
    private final long cancellationRetentionNanos;

    public AnalysisCoordinator(ObjectMapper mapper, CheckerLimits limits) {
        this.mapper = mapper.copy().enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        this.limits = limits;
        this.cancellationRetentionNanos = limits.analysisTimeout().plus(Duration.ofMinutes(1)).toNanos();
    }

    public Admission reserve() {
        if (!analysisSlot.tryAcquire()) {
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "checker_busy",
                    "java checker is already analyzing another project");
        }
        return new Admission(this);
    }

    public AnalysisResponse analyze(ValidatedRequest request, byte[] bundle) {
        try (Admission admission = reserve()) {
            return analyze(admission, request, bundle);
        }
    }

    public AnalysisResponse analyze(Admission admission, ValidatedRequest request, byte[] bundle) {
        admission.begin(this);
        ActiveRun run = new ActiveRun(limits.forceKillGrace());
        if (active.putIfAbsent(request.metadata().analysisId(), run) != null) {
            throw new ApiException(HttpStatus.CONFLICT, "analysis_already_running",
                    "analysis_id is already active");
        }

        Long pendingDeadline = takePendingCancellation(request.metadata().analysisId());
        if (pendingDeadline != null && pendingDeadline >= System.nanoTime()) {
            run.cancel();
        }

        Path directory = null;
        try {
            if (run.cancelled()) {
                return ResponseFactory.terminal(request.metadata(), "cancelled", "analysis_cancelled",
                        "java analysis was cancelled before worker startup");
            }
            directory = Files.createTempDirectory("binaryscan-java-analysis-");
            Path metadata = directory.resolve("metadata.json");
            Path source = directory.resolve("source.bundle");
            Path output = directory.resolve("response.json");
            Path log = directory.resolve("worker.log");
            mapper.writeValue(metadata.toFile(), request.metadata());
            Files.write(source, bundle);

            ProcessBuilder builder = new ProcessBuilder(workerCommand(metadata, source, output, directory));
            builder.environment().remove("JAVA_TOOL_OPTIONS");
            builder.environment().remove("_JAVA_OPTIONS");
            builder.environment().remove("JDK_JAVA_OPTIONS");
            builder.redirectErrorStream(true).redirectOutput(log.toFile());
            Process process = builder.start();
            run.attach(process);

            boolean exited = process.waitFor(limits.analysisTimeout().toMillis(), TimeUnit.MILLISECONDS);
            if (!exited) {
                run.cancel();
                return ResponseFactory.terminal(request.metadata(), "failed", "analysis_timeout",
                        "java analysis exceeded " + printable(limits.analysisTimeout()));
            }
            if (run.cancelled()) {
                return ResponseFactory.terminal(request.metadata(), "cancelled", "analysis_cancelled",
                        "java analysis was cancelled");
            }
            if (process.exitValue() != 0 || !Files.isRegularFile(output)) {
                return ResponseFactory.terminal(request.metadata(), "failed", "worker_failed",
                        "isolated Java analysis worker exited without a valid response");
            }
            long outputSize = Files.size(output);
            if (outputSize <= 0 || outputSize > limits.maxResponseBytes()) {
                return ResponseFactory.terminal(request.metadata(), "failed", "worker_response_too_large",
                        "isolated Java analysis worker produced an invalid response size");
            }
            AnalysisResponse response = mapper.readValue(output.toFile(), AnalysisResponse.class);
            validateWorkerResponse(request, response);
            return response;
        } catch (InterruptedException interrupted) {
            run.cancel();
            Thread.currentThread().interrupt();
            return ResponseFactory.terminal(request.metadata(), "cancelled", "request_interrupted",
                    "request thread was interrupted");
        } catch (IOException | RuntimeException error) {
            run.cancel();
            return ResponseFactory.terminal(request.metadata(), "failed", "worker_launch_failed",
                    "isolated Java analysis worker could not be launched or read");
        } finally {
            active.remove(request.metadata().analysisId(), run);
            run.cancelIfAlive();
            deleteDirectory(directory);
        }
    }

    public void cancel(String analysisId) {
        SourceValidator.requireValidUuid(analysisId);
        ActiveRun run = active.get(analysisId);
        if (run != null) {
            run.cancel();
            return;
        }
        recordPendingCancellation(analysisId);

        // Close the race where POST registers active work between the first
        // lookup and insertion of the cancellation tombstone.
        run = active.get(analysisId);
        if (run != null) {
            run.cancel();
            takePendingCancellation(analysisId);
        }
    }

    private synchronized void recordPendingCancellation(String analysisId) {
        long now = System.nanoTime();
        pendingCancellations.entrySet().removeIf(entry -> entry.getValue() < now);
        if (!pendingCancellations.containsKey(analysisId)
                && pendingCancellations.size() >= MAX_PENDING_CANCELLATIONS) {
            Iterator<String> oldest = pendingCancellations.keySet().iterator();
            if (oldest.hasNext()) {
                oldest.next();
                oldest.remove();
            }
        }
        pendingCancellations.put(analysisId, now + cancellationRetentionNanos);
    }

    private synchronized Long takePendingCancellation(String analysisId) {
        return pendingCancellations.remove(analysisId);
    }

    private List<String> workerCommand(Path metadata, Path source, Path output, Path temporaryDirectory) {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("-Djava.io.tmpdir=" + temporaryDirectory);
        command.add("-Xms64m");
        command.add("-Xmx1024m");
        command.add("-XX:+ExitOnOutOfMemoryError");

        Path location = codeLocation();
        if (Files.isRegularFile(location) && location.toString().endsWith(".jar")) {
            command.add("-Dloader.main=" + WorkerMain.class.getName());
            command.add("-cp");
            command.add(location.toString());
            command.add("org.springframework.boot.loader.launch.PropertiesLauncher");
        } else {
            command.add("-cp");
            command.add(System.getProperty("java.class.path"));
            command.add(WorkerMain.class.getName());
        }
        command.add(metadata.toString());
        command.add(source.toString());
        command.add(output.toString());
        command.add(Long.toString(limits.maxFileBytes()));
        command.add(Integer.toString(limits.maxFindings()));
        command.add(Integer.toString(limits.maxDiagnostics()));
        command.add(Integer.toString(limits.maxSnippetBytes()));
        command.add(Long.toString(limits.maxSourceBytes()));
        command.add(Long.toString(limits.maxResponseBytes()));
        return command;
    }

    private static Path codeLocation() {
        try {
            var location = WorkerMain.class.getProtectionDomain().getCodeSource().getLocation();
            if ("file".equalsIgnoreCase(location.getProtocol())) {
                return Path.of(location.toURI());
            }
            return new ApplicationHome(WorkerMain.class).getSource().toPath();
        } catch (Exception error) {
            throw new IllegalStateException("worker code location is unavailable", error);
        }
    }

    private static void validateWorkerResponse(ValidatedRequest request, AnalysisResponse response) {
        boolean valid = response != null
                && RESPONSE_SCHEMA.equals(response.schemaVersion())
                && request.metadata().analysisId().equals(response.analysisId())
                && STATUSES.contains(response.status())
                && response.identity() != null
                && PRODUCT.equals(response.identity().product())
                && VERSION.equals(response.identity().version())
                && RULESET.equals(response.identity().ruleset())
                && request.metadata().inputSha256().equalsIgnoreCase(response.inputSha256())
                && request.metadata().bundleSha256().equalsIgnoreCase(response.bundleSha256())
                && response.coverage() != null
                && response.coverage().filesTotal() == request.files().size()
                && response.coverage().filesParsed() + response.coverage().filesFailed()
                        == response.coverage().filesTotal()
                && response.coverage().filesRecovered() <= response.coverage().filesParsed()
                && response.coverage().filesAnalyzed() <= response.coverage().filesParsed()
                && response.summary() != null
                && response.findings() != null
                && response.diagnostics() != null
                && response.summary().findingCount() == response.findings().size()
                && response.summary().diagnosticCount() == response.diagnostics().size();
        if (!valid) {
            throw new IllegalStateException("worker response violates the Java checker contract");
        }
    }

    private static String printable(Duration duration) {
        return duration.toMinutes() + " minute(s)";
    }

    private static void deleteDirectory(Path directory) {
        if (directory == null || !Files.exists(directory)) {
            return;
        }
        try (var paths = Files.walk(directory)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // Best-effort cleanup; the container's tmpfs is also ephemeral.
                }
            });
        } catch (IOException ignored) {
            // Best-effort cleanup.
        }
    }

    public static final class Admission implements AutoCloseable {
        private final AnalysisCoordinator owner;
        private final AtomicBoolean begun = new AtomicBoolean();
        private final AtomicBoolean closed = new AtomicBoolean();

        private Admission(AnalysisCoordinator owner) {
            this.owner = owner;
        }

        private void begin(AnalysisCoordinator expectedOwner) {
            if (owner != expectedOwner || closed.get() || !begun.compareAndSet(false, true)) {
                throw new IllegalStateException("analysis admission is invalid or already used");
            }
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                owner.analysisSlot.release();
            }
        }
    }

    private static final class ActiveRun {
        private final AtomicBoolean cancelled = new AtomicBoolean();
        private final Duration grace;
        private volatile Process process;

        private ActiveRun(Duration grace) {
            this.grace = grace;
        }

        private synchronized void attach(Process process) {
            this.process = process;
            if (cancelled.get()) {
                terminate(process, grace);
            }
        }

        private void cancel() {
            cancelled.set(true);
            Process current = process;
            if (current != null) {
                terminate(current, grace);
            }
        }

        private boolean cancelled() {
            return cancelled.get();
        }

        private void cancelIfAlive() {
            Process current = process;
            if (current != null && current.isAlive()) {
                terminate(current, grace);
            }
        }

        private static void terminate(Process process, Duration grace) {
            process.destroy();
            try {
                if (!process.waitFor(grace.toMillis(), TimeUnit.MILLISECONDS)) {
                    process.destroyForcibly();
                    process.waitFor(grace.toMillis(), TimeUnit.MILLISECONDS);
                }
            } catch (InterruptedException interrupted) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
            }
        }
    }
}
