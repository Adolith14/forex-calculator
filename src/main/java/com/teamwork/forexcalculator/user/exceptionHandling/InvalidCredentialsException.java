package com.teamwork.forexcalculator.user.exceptionHandling;

public class InvalidCredentialsException extends RuntimeException{

    public InvalidCredentialsException(String message) {
        super(message);
    }

}
