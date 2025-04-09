package com.teamwork.forexcalculator.user.service;

public interface EmailService {
    String sendLoginToken (String email, String token);
}
