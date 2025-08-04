package com.teamwork.forexcalculator.user.exceptionHandling;

public class TokenRefreshException extends RuntimeException {
    public TokenRefreshException(String message) {
        super(message);
    }
}