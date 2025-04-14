package com.teamwork.forexcalculator.user.dto;

import lombok.Data;

@Data
public class ResetPasswordDTO{
    private String email;
    private String otpCode;
    private String newPassword;
    private String confirmPassword;
}
