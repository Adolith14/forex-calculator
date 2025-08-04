package com.teamwork.forexcalculator.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class ChangePasswordDTO {

    @NotBlank(message = "Current password is required")
    private String oldPassword;

    @NotBlank(message = "New password is required")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?]).{8,}$",
            message = "New password must be at least 8 characters long and include uppercase, lowercase, digit, and special character"
    )
    private String newPassword;

    @NotBlank(message = "Please confirm your new password")
    private String confirmPassword;
}

