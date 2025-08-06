package com.teamwork.forexcalculator.user.exceptionHandling;

public class InvalidPhoneNumberException extends RuntimeException {
    public InvalidPhoneNumberException(String message) {
        super(message);
    }
}
