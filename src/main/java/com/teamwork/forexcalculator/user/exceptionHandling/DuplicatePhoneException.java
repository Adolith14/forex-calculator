package com.teamwork.forexcalculator.user.exceptionHandling;

public class DuplicatePhoneException extends RuntimeException {

    public DuplicatePhoneException(String message) {
        super(message);
    }
}
