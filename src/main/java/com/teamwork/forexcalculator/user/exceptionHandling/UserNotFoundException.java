package com.teamwork.forexcalculator.user.exceptionHandling;

public class UserNotFoundException extends RuntimeException {

    public UserNotFoundException(String message) {
        super(message);
    }
}
