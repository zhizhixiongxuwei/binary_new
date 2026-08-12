package com.binaryscan.javachecker.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

import com.binaryscan.javachecker.service.Utf8Text;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiError> api(ApiException error) {
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(error.status());
        if (error.status() == HttpStatus.TOO_MANY_REQUESTS) {
            builder.header("Retry-After", "1");
        }
        return builder.body(new ApiError(error.code(), error.getMessage()));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ApiError> tooLarge(MaxUploadSizeExceededException ignored) {
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .body(new ApiError("source_too_large", "multipart request exceeds the configured limit"));
    }

    @ExceptionHandler(MissingServletRequestPartException.class)
    public ResponseEntity<ApiError> missingPart(MissingServletRequestPartException error) {
        return ResponseEntity.badRequest().body(new ApiError("invalid_request", safeMessage(error)));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> unexpected(Exception ignored) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiError("internal_error", "java checker could not complete the request"));
    }

    private static String safeMessage(Exception error) {
        String message = error.getMessage();
        if (message == null || message.isBlank()) {
            return "request is invalid";
        }
        int newline = message.indexOf('\n');
        return Utf8Text.message(newline >= 0 ? message.substring(0, newline) : message);
    }
}
