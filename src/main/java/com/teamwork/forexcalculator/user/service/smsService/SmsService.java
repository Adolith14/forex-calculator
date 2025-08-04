package com.teamwork.forexcalculator.user.service.smsService;

import com.teamwork.forexcalculator.user.service.smsService.SmsGatewayConfig.SmsGatewayProperties;
import com.teamwork.forexcalculator.user.repository.PhoneVerificationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class SmsService {
    private final PhoneVerificationRepository phoneVerificationRepo;
    private final SmsGatewayProperties smsGatewayProperties;

    public void sendOtpCode(String phoneNumber, String otpCode) {
        String message = "Your verification code is: " + otpCode;
        sendSms(phoneNumber, message);
    }

    public void sendLoginToken(String phoneNumber, String token) {
        String message = "Your login token is: " + token;
        sendSms(phoneNumber, message);
    }

    private void sendSms(String phoneNumber, String message) {
        if (smsGatewayProperties.isEnabled()) {
            sendViaRealGateway(phoneNumber, message);
        } else {
            log.info("SMS to {}: {}", phoneNumber, message);
        }
    }

    private void sendViaRealGateway(String phoneNumber, String message) {
        log.warn("Would send SMS via {} to {}: {}",
                smsGatewayProperties.getUrl(), phoneNumber, message);
        // Actual implementation would go here
    }
}