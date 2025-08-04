package com.teamwork.forexcalculator.user.exceptionHandling;

public class ExpiredOtpException extends RuntimeException {

    public ExpiredOtpException(String message) {
        super(message);
    }
}
