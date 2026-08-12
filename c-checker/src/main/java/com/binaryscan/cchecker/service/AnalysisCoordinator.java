package com.binaryscan.cchecker.service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.binaryscan.cchecker.api.AnalysisResponse;
import com.binaryscan.cchecker.api.ApiException;

@Service
public class AnalysisCoordinator {
    private static final int MAX_PENDING_CANCELLATIONS = 4096;
    private static final Pattern ANALYSIS_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");

    private final Semaphore concurrency = new Semaphore(1, true);
    private final AtomicReference<AnalysisRunContext> active = new AtomicReference<>();
    private final Map<String, Long> pendingCancellations = new ConcurrentHashMap<>();
    private final AnalysisEngine engine;
    private final CheckerLimits limits;
    private final long cancellationRetentionNanos;

    public AnalysisCoordinator(AnalysisEngine engine, CheckerLimits limits) {
        this.engine = engine;
        this.limits = limits;
        this.cancellationRetentionNanos = limits.analysisTimeout()
                .plus(Duration.ofMinutes(1))
                .toNanos();
    }

    public AnalysisResponse analyze(ValidatedRequest request) {
        if (!concurrency.tryAcquire()) {
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "analysis_busy",
                    "the checker already has an active analysis");
        }
        AnalysisRunContext context = new AnalysisRunContext(request.metadata().analysisId(), limits.analysisTimeout());
        active.set(context);
        Long cancellationDeadline = pendingCancellations.remove(context.analysisId());
        if (cancellationDeadline != null && cancellationDeadline >= System.nanoTime()) {
            context.cancel();
        }
        try {
            return engine.analyze(request, context);
        } finally {
            active.compareAndSet(context, null);
            concurrency.release();
        }
    }

    public void cancel(String analysisId) {
        AnalysisRunContext context = active.get();
        if (context != null && context.analysisId().equals(analysisId)) {
            context.cancel();
            return;
        }
        if (analysisId == null || !ANALYSIS_ID.matcher(analysisId).matches()) {
            return;
        }
        long now = System.nanoTime();
        if (pendingCancellations.size() >= MAX_PENDING_CANCELLATIONS) {
            pendingCancellations.entrySet().removeIf(entry -> entry.getValue() < now);
        }
        if (pendingCancellations.size() < MAX_PENDING_CANCELLATIONS
                || pendingCancellations.containsKey(analysisId)) {
            pendingCancellations.put(analysisId, now + cancellationRetentionNanos);
        }
    }
}
