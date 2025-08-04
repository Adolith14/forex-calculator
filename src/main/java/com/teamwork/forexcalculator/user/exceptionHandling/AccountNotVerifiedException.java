package com.teamwork.forexcalculator.user.exceptionHandling;


public class AccountNotVerifiedException extends RuntimeException{
    public AccountNotVerifiedException(String message) {
        super(message);
    }
}
