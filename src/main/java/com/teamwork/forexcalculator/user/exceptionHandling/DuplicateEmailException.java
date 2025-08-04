package com.teamwork.forexcalculator.user.exceptionHandling;

public class DuplicateEmailException extends RuntimeException {

    public DuplicateEmailException(String message) {
        super(message);
    }
}
