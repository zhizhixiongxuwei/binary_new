package com.binaryscan.javachecker.engine;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.nio.charset.CodingErrorAction;
import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;

import com.github.javaparser.Position;
import com.github.javaparser.Range;

class SnippetExtractorTest {
    @Test
    void indexesMaxFileOnceForManyFindingsOnOneLongLine() {
        int maxFileBytes = 8 * 1024 * 1024;
        String source = "x".repeat(maxFileBytes);
        SnippetExtractor extractor = new SnippetExtractor(source, 1024);

        for (int index = 0; index < 10000; index++) {
            int column = 1 + (index * 7919) % maxFileBytes;
            var snippet = extractor.extract(new Range(
                    new Position(1, column), new Position(1, Math.min(maxFileBytes, column + 3))));
            assertThat(snippet.text().getBytes(StandardCharsets.UTF_8)).hasSizeLessThanOrEqualTo(1024);
        }
    }

    @Test
    void removesControlsRejectedByTheBackendTextContract() {
        String source = "class Safe {\n\t// before\f\u0001after\n}\n";
        SnippetExtractor extractor = new SnippetExtractor(source, 1024);

        var snippet = extractor.extract(new Range(new Position(2, 5), new Position(2, 10)));

        assertThat(snippet.text()).contains("\t", "before  after");
        assertThat(snippet.text()).doesNotContain("\f", "\u0001");
    }

    @Test
    void longSupplementaryPlaneLineNeverSplitsASurrogatePair() throws Exception {
        String source = "\ud83d\ude00".repeat(5000);
        SnippetExtractor extractor = new SnippetExtractor(source, 1024);

        var snippet = extractor.extract(new Range(
                new Position(1, source.length() - 3), new Position(1, source.length() - 1)));

        assertThat(snippet.text().getBytes(StandardCharsets.UTF_8)).hasSizeLessThanOrEqualTo(1024);
        StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(snippet.text().getBytes(StandardCharsets.UTF_8)));
        assertThat(snippet.text()).doesNotContain("\ufffd");
    }
}
