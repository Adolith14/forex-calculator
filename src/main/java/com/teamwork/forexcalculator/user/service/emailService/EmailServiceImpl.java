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
        String messageText = "Hello,\n\n"
                + "A login OTP has been generated for your account.\n\n"
                + "Please use the following OTP to complete your login:\n\n"
                + "🔐 OTP: " + token + "\n\n"
                + "This OTP is valid for 5 minutes.\n\n"
                + "If you did not initiate this login, please ignore this email.\n\n"
                + "Regards,\n"
                + "The Lyntel Team";

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Complete Your Login – OTP Inside ✅");
        message.setText(messageText);
        message.setFrom("demodeveloper14@gmail.com");

        javaMailSender.send(message);

        return "Login token send to your email";
    }

    @Override
    public String sendOtpCode(String email, String otp) {
        String messageText = "Hello,\n\n"
                + "Thank you for registering with Lyntel's Software.\n\n"
                + "Please use the following OTP to verify your email:\n\n"
                + "🔐 OTP: " + otp + "\n\n"
                + "This OTP is valid for 60 minutes.\n\n"
                + "If you did not request this, please ignore this email.\n\n"
                + "Regards,\n"
                + "The Lyntel Team";
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Email Verification OTP");
        message.setText(messageText);
        message.setFrom("your_email@example.com");
        javaMailSender.send(message);

        return "Email verification OTP send to your email";
    }

    @Override
    public String resetPasswordEmail(String email, String otp) {
        String messageText = "Hello,\n\n"
                + "We received a request to reset your password for your Forex Calculator account.\n\n"
                + "🔐 OTP: " + otp + "\n\n"
                + "To reset your password, click the link below:\n"
                + "👉 http://localhost:8080/api/auth/reset-password?email=" + email + "&otp=" + otp + "\n\n"
                + "This link is valid for 10 minutes.\n\n"
                + "If you didn’t request a password reset, you can safely ignore this email.\n\n"
                + "Regards,\n"
                + "The Forex Calculator Team";
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Reset Your Password – Forex Calculator");
        message.setText(messageText);
        message.setFrom("your_email@example.com");
        javaMailSender.send(message);

        return "Email verification OTP send to your email";
    }
}
