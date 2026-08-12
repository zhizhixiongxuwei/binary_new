package com.binaryscan.javachecker.service;

import java.nio.charset.StandardCharsets;

public final class Utf8Text {
    public static final int MESSAGE_BYTES = 2048;
    public static final int CALLABLE_KIND_BYTES = 32;
    public static final int CALLABLE_TYPE_BYTES = 1024;
    public static final int CALLABLE_NAME_BYTES = 512;
    public static final int CALLABLE_SIGNATURE_BYTES = 2048;

    private Utf8Text() {
    }

    public static String bound(String value, int maxBytes, String fallback) {
        String input = value == null || value.isBlank() ? fallback : value;
        if (input == null) {
            input = "";
        }
        StringBuilder output = new StringBuilder(Math.min(input.length(), maxBytes));
        int used = 0;
        for (int offset = 0; offset < input.length();) {
            char current = input.charAt(offset);
            int codePoint;
            int consumed;
            if (Character.isHighSurrogate(current)) {
                if (offset + 1 < input.length() && Character.isLowSurrogate(input.charAt(offset + 1))) {
                    codePoint = Character.toCodePoint(current, input.charAt(offset + 1));
                    consumed = 2;
                } else {
                    codePoint = 0xfffd;
                    consumed = 1;
                }
            } else if (Character.isLowSurrogate(current)) {
                codePoint = 0xfffd;
                consumed = 1;
            } else {
                codePoint = current;
                consumed = 1;
            }
            int encoded = utf8Bytes(codePoint);
            if (used + encoded > maxBytes) {
                break;
            }
            output.appendCodePoint(codePoint);
            used += encoded;
            offset += consumed;
        }
        return output.toString();
    }

    public static String required(String value, int maxBytes, String fallback) {
        String bounded = bound(value, maxBytes, fallback);
        return bounded.isBlank() ? bound(fallback, maxBytes, "unknown") : bounded;
    }

    public static String message(String value) {
        String input = value == null || value.isBlank() ? "analysis message unavailable" : value;
        StringBuilder singleLine = new StringBuilder(input.length());
        for (int offset = 0; offset < input.length();) {
            int codePoint = input.codePointAt(offset);
            if (codePoint == '\r' || codePoint == '\n' || Character.isISOControl(codePoint)) {
                singleLine.append(' ');
            } else {
                singleLine.appendCodePoint(codePoint);
            }
            offset += Character.charCount(codePoint);
        }
        return required(singleLine.toString(), MESSAGE_BYTES, "analysis message unavailable");
    }

    public static int bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private static int utf8Bytes(int codePoint) {
        if (codePoint <= 0x7f) {
            return 1;
        }
        if (codePoint <= 0x7ff) {
            return 2;
        }
        if (codePoint <= 0xffff) {
            return 3;
        }
        return 4;
    }
}
