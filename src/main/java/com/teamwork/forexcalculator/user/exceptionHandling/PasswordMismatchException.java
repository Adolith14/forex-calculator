package com.teamwork.forexcalculator.user.exceptionHandling;

public class PasswordMismatchException extends RuntimeException {

    public PasswordMismatchException(String message) {
        super(message);
    }

}
