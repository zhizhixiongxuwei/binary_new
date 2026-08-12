package com.binaryscan.javachecker.worker;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;

import org.junit.jupiter.api.Test;

class BoundedOutputStreamTest {
    @Test
    void refusesTheWriteBeforeTheBackingOutputCanExceedItsLimit() throws Exception {
        ByteArrayOutputStream backing = new ByteArrayOutputStream();
        BoundedOutputStream bounded = new BoundedOutputStream(backing, 8);
        bounded.write(new byte[] {1, 2, 3, 4});

        assertThatThrownBy(() -> bounded.write(new byte[] {5, 6, 7, 8, 9}))
                .isInstanceOf(BoundedOutputStream.ResponseLimitExceededException.class);
        assertThat(backing.toByteArray()).containsExactly(1, 2, 3, 4);

        bounded.write(new byte[] {5, 6, 7, 8});
        assertThat(backing.size()).isEqualTo(8);
    }
}
