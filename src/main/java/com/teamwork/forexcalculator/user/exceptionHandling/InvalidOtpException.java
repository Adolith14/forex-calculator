package com.teamwork.forexcalculator.user.exceptionHandling;

public class InvalidOtpException extends RuntimeException {

    public InvalidOtpException(String message) {
        super(message);
    }

}
