package com.teamwork.forexcalculator.user.exceptionHandling;

public class SmsSendException extends RuntimeException {

    public SmsSendException(String message) {
        super(message);
    }

}
