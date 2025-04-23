package com.teamwork.forexcalculator.user.dto;

import lombok.Data;

@Data
public class LoginOtpVerifyDTO {
    private String email;
    private String code;
}
