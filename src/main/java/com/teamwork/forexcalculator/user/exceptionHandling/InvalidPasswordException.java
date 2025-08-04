package com.teamwork.forexcalculator.user.exceptionHandling;

public class InvalidPasswordException extends RuntimeException{

    public InvalidPasswordException(String message) {
        super(message);
    }

}
