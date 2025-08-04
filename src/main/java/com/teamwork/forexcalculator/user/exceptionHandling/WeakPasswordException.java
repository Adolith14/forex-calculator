package com.teamwork.forexcalculator.user.exceptionHandling;

public class WeakPasswordException extends RuntimeException {

    public WeakPasswordException(String message) {
        super(message);
    }
}
