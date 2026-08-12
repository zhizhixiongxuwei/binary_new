package com.binaryscan.javachecker.engine;

import com.binaryscan.javachecker.api.AnalysisResponse;

final class JsonSize {
    private JsonSize() {
    }

    static long finding(AnalysisResponse.Finding finding) {
        return 512L
                + string(finding.ruleId()) + string(finding.cwe()) + string(finding.severity())
                + string(finding.message()) + file(finding.file()) + callable(finding.callable())
                + string(finding.snippet());
    }

    static long diagnostic(AnalysisResponse.Diagnostic diagnostic) {
        return 256L + string(diagnostic.code()) + string(diagnostic.message())
                + string(diagnostic.severity()) + file(diagnostic.file());
    }

    private static long file(AnalysisResponse.FileIdentity file) {
        return file == null ? 4 : 128L + string(file.resultId())
                + string(file.logicalPath()) + string(file.binaryName());
    }

    private static long callable(AnalysisResponse.Callable callable) {
        return callable == null ? 4 : 128L + string(callable.kind()) + string(callable.typeName())
                + string(callable.name()) + string(callable.signature());
    }

    private static long string(String value) {
        if (value == null) {
            return 4;
        }
        long bytes = 2;
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            if (codePoint == '"' || codePoint == '\\') {
                bytes += 2;
            } else if (codePoint < 0x20) {
                bytes += 6;
            } else if (codePoint <= 0x7f) {
                bytes += 1;
            } else if (codePoint <= 0x7ff) {
                bytes += 2;
            } else if (codePoint <= 0xffff) {
                bytes += 3;
            } else {
                bytes += 4;
            }
            offset += Character.charCount(codePoint);
        }
        return bytes;
    }
}
