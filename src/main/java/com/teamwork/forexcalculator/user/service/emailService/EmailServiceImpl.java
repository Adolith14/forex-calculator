package com.teamwork.forexcalculator.user.service.emailService;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender javaMailSender;

    public EmailServiceImpl(JavaMailSender javaMailSender) {
        this.javaMailSender = javaMailSender;
    }

    @Override
    public String sendLoginToken(String email, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Your Login Token (MFA)");
        message.setText("Use this token to log in: " + token);
        message.setFrom("demodeveloper14@gmail.com");

        javaMailSender.send(message);

        return "Login token send to your email";
    }

    @Override
    public String sendOtpCode(String email, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Email Verification OTP");
        message.setText("Your OTP code is: " + otp);
        message.setFrom("your_email@example.com");
        javaMailSender.send(message);

        return "Email verification OTP send to your email";
    }
}
