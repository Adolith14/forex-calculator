package com.teamwork.forexcalculator.user.service.smsService;

import com.teamwork.forexcalculator.user.service.smsService.SmsGatewayConfig.SmsGatewayProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;
import com.teamwork.forexcalculator.user.exceptionHandling.InvalidPhoneNumberException;

@Slf4j
@Service
@RequiredArgsConstructor
public class SmsService {
    private final SmsGatewayProperties smsGatewayProperties;
    private final PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();

    public void sendOtpCode(String phoneNumber, String countryCode, String otpCode) {
        String formattedNumber = validateAndFormatNumber(phoneNumber, countryCode);
        String maskedOtp = maskOtp(otpCode);
        String message = String.format("Your %s verification code is: %s",
                getCountryName(countryCode), maskedOtp);
        sendSms(formattedNumber, message);
    }

    public void sendLoginToken(String phoneNumber, String countryCode, String token) {
        String formattedNumber = validateAndFormatNumber(phoneNumber, countryCode);
        String message = "Your login token is: " + token;
        sendSms(formattedNumber, message);
    }

    private String validateAndFormatNumber(String phoneNumber, String countryCode) {
        try {
            Phonenumber.PhoneNumber number = phoneUtil.parse(phoneNumber, countryCode);
            if (!phoneUtil.isValidNumber(number)) {
                throw new InvalidPhoneNumberException("Invalid phone number for country: " + countryCode);
            }
            return phoneUtil.format(number, PhoneNumberUtil.PhoneNumberFormat.E164);
        } catch (NumberParseException e) {
            throw new InvalidPhoneNumberException("Failed to parse phone number: " + e.getMessage());
        }
    }

    private String maskOtp(String otp) {
        if (otp.length() <= 4) return "****";
        return otp.substring(0, 2) + "****" + otp.substring(otp.length() - 2);
    }

    private String getCountryName(String countryCode) {
        // Implement your country code mapping or use a service
        return switch (countryCode.toUpperCase()) {
            case "US" -> "US";
            case "NG" -> "Nigeria";
            case "GB" -> "UK";
            default -> "";
        };
    }

    private void sendSms(String internationalNumber, String message) {
        if (smsGatewayProperties.isEnabled()) {
            sendViaRealGateway(internationalNumber, message);
        } else {
            log.info("SMS to {}: {}", internationalNumber, message);
        }
    }

    private void sendViaRealGateway(String internationalNumber, String message) {
        // Actual implementation for your SMS gateway
        log.info("Sending via {} to {}: {}",
                smsGatewayProperties.getUrl(),
                internationalNumber,
                message);
    }
}