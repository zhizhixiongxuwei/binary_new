package com.binaryscan.javachecker.service;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "java-checker.limits")
public record CheckerLimits(
        long maxSourceBytes,
        int maxFiles,
        long maxFileBytes,
        int maxFindings,
        int maxDiagnostics,
        int maxSnippetBytes,
        long maxResponseBytes,
        Duration analysisTimeout,
        Duration forceKillGrace) {

    public static CheckerLimits defaults() {
        return new CheckerLimits(
                128L * 1024 * 1024,
                3000,
                8L * 1024 * 1024,
                10000,
                1000,
                1024,
                32L * 1024 * 1024,
                Duration.ofMinutes(10),
                Duration.ofSeconds(2));
    }
}
