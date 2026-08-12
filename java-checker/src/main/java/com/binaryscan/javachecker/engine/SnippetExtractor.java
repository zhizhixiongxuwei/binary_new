package com.binaryscan.javachecker.engine;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import com.github.javaparser.Range;

final class SnippetExtractor {
    private static final int CONTEXT_LINES = 3;

    private final String source;
    private final int[] lineStarts;
    private final int maxBytes;

    SnippetExtractor(String source, int maxBytes) {
        this.source = sanitize(source);
        this.lineStarts = indexLines(this.source);
        this.maxBytes = maxBytes;
    }

    Snippet extract(Range range) {
        int lines = lineStarts.length;
        int hitStart = clamp(range.begin.line, 1, lines);
        int hitEnd = clamp(range.end.line, hitStart, lines);
        int start = Math.max(1, hitStart - CONTEXT_LINES);
        int end = Math.min(lines, hitEnd + CONTEXT_LINES);

        while (characterSpan(start, end) > maxBytes && (start < hitStart || end > hitEnd)) {
            int before = hitStart - start;
            int after = end - hitEnd;
            if (after >= before && end > hitEnd) {
                end--;
            } else if (start < hitStart) {
                start++;
            } else {
                end--;
            }
        }
        if (characterSpan(start, end) > maxBytes) {
            return new Snippet(hitWindow(hitStart, hitEnd, range.begin.column - 1), hitStart);
        }

        String candidate = join(start, end);
        if (utf8Length(candidate) <= maxBytes) {
            return new Snippet(candidate, start);
        }

        String hit = join(hitStart, hitEnd);
        return new Snippet(truncateAround(hit, range.begin.column - 1, maxBytes), hitStart);
    }

    private int characterSpan(int startLine, int endLine) {
        return Math.max(0, lineContentEnd(endLine) - lineStarts[startLine - 1]);
    }

    private String hitWindow(int hitStart, int hitEnd, int preferredColumn) {
        int lineStart = lineStarts[hitStart - 1];
        int hitEndOffset = lineContentEnd(hitEnd);
        int preferred = clamp(lineStart + preferredColumn, lineStart, hitEndOffset);
        int left = Math.max(lineStart, preferred - maxBytes / 2);
        int right = Math.min(hitEndOffset, left + maxBytes);
        if (right - left < maxBytes) {
            left = Math.max(lineStart, right - maxBytes);
        }
        left = alignBoundaryBackward(source, left, lineStart);
        right = alignBoundaryForward(source, right, hitEndOffset);
        preferred = alignBoundaryBackward(source, preferred, lineStart);
        String window = source.substring(left, right);
        return truncateAround(window, preferred - left, maxBytes);
    }

    private String join(int startLine, int endLine) {
        int start = lineStarts[startLine - 1];
        int end = lineContentEnd(endLine);
        return source.substring(start, Math.max(start, end));
    }

    private int lineContentEnd(int line) {
        if (line >= lineStarts.length) {
            return source.length();
        }
        int end = lineStarts[line];
        if (end > 0 && source.charAt(end - 1) == '\n') {
            end--;
            if (end > 0 && source.charAt(end - 1) == '\r') {
                end--;
            }
        } else if (end > 0 && source.charAt(end - 1) == '\r') {
            end--;
        }
        return end;
    }

    private static int[] indexLines(String source) {
        int[] starts = new int[Math.max(16, Math.min(4096, source.length() / 32 + 2))];
        int count = 1;
        starts[0] = 0;
        for (int index = 0; index < source.length(); index++) {
            char current = source.charAt(index);
            if (current == '\r') {
                if (index + 1 < source.length() && source.charAt(index + 1) == '\n') {
                    index++;
                }
                if (count == starts.length) {
                    starts = Arrays.copyOf(starts, starts.length * 2);
                }
                starts[count++] = index + 1;
            } else if (current == '\n') {
                if (count == starts.length) {
                    starts = Arrays.copyOf(starts, starts.length * 2);
                }
                starts[count++] = index + 1;
            }
        }
        return Arrays.copyOf(starts, count);
    }

    private static String sanitize(String source) {
        StringBuilder clean = null;
        for (int index = 0; index < source.length(); index++) {
            char value = source.charAt(index);
            boolean forbidden = Character.isISOControl(value)
                    && value != '\n' && value != '\r' && value != '\t';
            if (forbidden && clean == null) {
                clean = new StringBuilder(source);
            }
            if (forbidden) {
                clean.setCharAt(index, ' ');
            }
        }
        return clean == null ? source : clean.toString();
    }

    private static String truncateAround(String value, int preferredCharacter, int maxBytes) {
        if (utf8Length(value) <= maxBytes) {
            return value;
        }
        int center = clamp(preferredCharacter, 0, value.length());
        center = alignBoundaryBackward(value, center, 0);
        int left = center;
        int right = center;
        int used = 0;
        while (left > 0 || right < value.length()) {
            boolean tookRight = false;
            if (right < value.length()) {
                int codePoint = value.codePointAt(right);
                int characters = Character.charCount(codePoint);
                int bytes = utf8CodePointLength(codePoint);
                if (used + bytes <= maxBytes) {
                    right += characters;
                    used += bytes;
                    tookRight = true;
                }
            }
            if (left > 0) {
                int codePoint = value.codePointBefore(left);
                int characters = Character.charCount(codePoint);
                int bytes = utf8CodePointLength(codePoint);
                if (used + bytes <= maxBytes) {
                    left -= characters;
                    used += bytes;
                } else if (!tookRight) {
                    break;
                }
            } else if (!tookRight) {
                break;
            }
        }
        return value.substring(left, right);
    }

    private static int utf8Length(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private static int utf8CodePointLength(int codePoint) {
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

    private static int alignBoundaryBackward(String value, int offset, int minimum) {
        int aligned = clamp(offset, minimum, value.length());
        if (aligned > minimum && aligned < value.length()
                && Character.isLowSurrogate(value.charAt(aligned))
                && Character.isHighSurrogate(value.charAt(aligned - 1))) {
            aligned--;
        }
        return aligned;
    }

    private static int alignBoundaryForward(String value, int offset, int maximum) {
        int aligned = clamp(offset, 0, Math.min(maximum, value.length()));
        if (aligned > 0 && aligned < maximum && aligned < value.length()
                && Character.isHighSurrogate(value.charAt(aligned - 1))
                && Character.isLowSurrogate(value.charAt(aligned))) {
            aligned++;
        }
        return aligned;
    }

    private static int clamp(int value, int minimum, int maximum) {
        return Math.max(minimum, Math.min(maximum, value));
    }

    record Snippet(String text, int startLine) {
    }
}
