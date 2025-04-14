package com.teamwork.forexcalculator.user.service.emailService;

public interface EmailService {

    String sendLoginToken(String email, String token);
    String sendOtpCode(String email, String otp);
}
