package com.teamwork.forexcalculator.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class PhoneVerifyDTO {

    @NotBlank(message = "Phone number is required")
    @Pattern(regexp = "^(?:\\+255|0)?[67]\\d{8}$", message = "Invalid Tanzania phone number")
    private String phoneNumber;

    @NotBlank(message = "OTP code is required")
    @Pattern(regexp = "\\d{6}", message = "OTP code must be 6 digits")
    private String otpCode;
}
