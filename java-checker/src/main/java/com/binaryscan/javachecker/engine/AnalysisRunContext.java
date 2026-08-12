package com.binaryscan.javachecker.engine;

import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

public final class AnalysisRunContext {
    private final BooleanSupplier cancelled;

    public AnalysisRunContext(BooleanSupplier cancelled) {
        this.cancelled = cancelled;
    }

    public void checkpoint() {
        if (Thread.currentThread().isInterrupted() || cancelled.getAsBoolean()) {
            throw new CancellationException("analysis cancelled");
        }
    }
}
