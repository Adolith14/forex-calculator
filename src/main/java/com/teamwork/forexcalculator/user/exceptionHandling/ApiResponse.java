package com.teamwork.forexcalculator.user.exceptionHandling;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ApiResponse<T> {
    private boolean success;
    private T data;
    private String error;

    public ApiResponse(boolean success, T data) {
        this(success, data, null);
    }

    public ApiResponse(boolean success, String error) {
        this(success, null, error);
    }
}