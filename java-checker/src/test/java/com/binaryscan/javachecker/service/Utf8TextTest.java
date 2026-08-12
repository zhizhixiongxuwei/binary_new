package com.binaryscan.javachecker.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class Utf8TextTest {
    @Test
    void truncatesOnCodePointAndUtf8ByteBoundaries() throws Exception {
        String bounded = Utf8Text.bound("\u754c".repeat(1000), 1024, "fallback");

        assertThat(Utf8Text.bytes(bounded)).isLessThanOrEqualTo(1024);
        assertThat(bounded).doesNotContain("\ufffd");
        StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bounded.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void replacesUnpairedSurrogatesAndBoundsSingleLineMessages() {
        String bounded = Utf8Text.bound("before\ud800after", 128, "fallback");
        String message = Utf8Text.message("line one\nline two\0" + "\u754c".repeat(2000));

        assertThat(bounded).isEqualTo("before\ufffdafter");
        assertThat(message).doesNotContain("\n", "\0");
        assertThat(Utf8Text.bytes(message)).isLessThanOrEqualTo(Utf8Text.MESSAGE_BYTES);
    }
}
