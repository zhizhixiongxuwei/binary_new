package com.binaryscan.javachecker.engine;

record RuleDefinition(String ruleId, String cwe, String severity) {
    RuleDefinition {
        if (!("LOW".equals(severity) || "MEDIUM".equals(severity)
                || "HIGH".equals(severity) || "CRITICAL".equals(severity))) {
            throw new IllegalArgumentException("unsupported severity: " + severity);
        }
    }
}
