package com.teamwork.forexcalculator.user.dto;

import lombok.Data;

@Data
public class EmailVerifyDTO {
    private String email;
    private String otpCode;
}
