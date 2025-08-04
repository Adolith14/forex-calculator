package com.teamwork.forexcalculator.user.exceptionHandling;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@AllArgsConstructor
public class ApiErrorResponse {
    private int status;
    private String message;
    private Map<String, String> fieldErrors;
    private String timestamp;

    public ApiErrorResponse(int status, String message) {
        this(status, message, null, LocalDateTime.now().toString());
    }

    public ApiErrorResponse(int status, String message, Map<String, String> fieldErrors) {
        this(status, message, fieldErrors, LocalDateTime.now().toString());
    }
}
