package com.teamwork.forexcalculator.user.dto;

import lombok.Data;

@Data
public class OtpVerifyDto {
    private String email;
    private String otpCode;
}
