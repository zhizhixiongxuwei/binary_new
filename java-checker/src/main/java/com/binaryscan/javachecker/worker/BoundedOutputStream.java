package com.binaryscan.javachecker.worker;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

final class BoundedOutputStream extends FilterOutputStream {
    private final long limit;
    private long written;

    BoundedOutputStream(OutputStream output, long limit) {
        super(output);
        if (limit <= 0) {
            throw new IllegalArgumentException("output limit must be positive");
        }
        this.limit = limit;
    }

    @Override
    public void write(int value) throws IOException {
        reserve(1);
        out.write(value);
    }

    @Override
    public void write(byte[] value, int offset, int length) throws IOException {
        if (offset < 0 || length < 0 || offset + length > value.length) {
            throw new IndexOutOfBoundsException();
        }
        reserve(length);
        out.write(value, offset, length);
    }

    private void reserve(int bytes) throws ResponseLimitExceededException {
        if (bytes > limit - written) {
            throw new ResponseLimitExceededException(limit);
        }
        written += bytes;
    }

    static boolean isLimitExceeded(Throwable error) {
        Throwable current = error;
        while (current != null) {
            if (current instanceof ResponseLimitExceededException) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    static final class ResponseLimitExceededException extends IOException {
        private ResponseLimitExceededException(long limit) {
            super("serialized response exceeds " + limit + " bytes");
        }
    }
}
