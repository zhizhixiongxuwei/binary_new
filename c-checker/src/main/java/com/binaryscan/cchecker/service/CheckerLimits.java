package com.binaryscan.cchecker.service;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "c-checker.limits")
public record CheckerLimits(
        long maxSourceBytes,
        int maxFunctions,
        int maxFindings,
        int maxDiagnostics,
        int maxSnippetBytes,
        Duration analysisTimeout) {
}
