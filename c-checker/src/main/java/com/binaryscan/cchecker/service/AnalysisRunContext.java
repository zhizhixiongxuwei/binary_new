package com.binaryscan.cchecker.service;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

public final class AnalysisRunContext {
    public enum StopReason {
        CANCELLED,
        TIMEOUT
    }

    private final String analysisId;
    private final long deadlineNanos;
    private final AtomicBoolean cancelled = new AtomicBoolean();

    public AnalysisRunContext(String analysisId, Duration timeout) {
        this.analysisId = analysisId;
        long timeoutNanos = timeout.toNanos();
        long now = System.nanoTime();
        this.deadlineNanos = timeoutNanos >= Long.MAX_VALUE - now ? Long.MAX_VALUE : now + timeoutNanos;
    }

    public String analysisId() {
        return analysisId;
    }

    public void cancel() {
        cancelled.set(true);
    }

    public void checkpoint() {
        if (cancelled.get() || Thread.currentThread().isInterrupted()) {
            throw new AnalysisStoppedException(StopReason.CANCELLED);
        }
        if (System.nanoTime() >= deadlineNanos) {
            throw new AnalysisStoppedException(StopReason.TIMEOUT);
        }
    }

    public static final class AnalysisStoppedException extends RuntimeException {
        private final StopReason reason;

        public AnalysisStoppedException(StopReason reason) {
            super(reason.name().toLowerCase());
            this.reason = reason;
        }

        public StopReason reason() {
            return reason;
        }
    }
}
