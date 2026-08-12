package com.binaryscan.javachecker.api;

import org.springframework.http.HttpStatus;

import com.binaryscan.javachecker.service.Utf8Text;

public final class ApiException extends RuntimeException {
    private final HttpStatus status;
    private final String code;

    public ApiException(HttpStatus status, String code, String message) {
        super(Utf8Text.message(message));
        this.status = status;
        this.code = code;
    }

    public HttpStatus status() {
        return status;
    }

    public String code() {
        return code;
    }
}
