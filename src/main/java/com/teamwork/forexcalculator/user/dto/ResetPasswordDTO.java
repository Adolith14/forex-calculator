package com.teamwork.forexcalculator.user.dto;

import jakarta.validation.Payload;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@PasswordMatches(message = "New password and confirm password do not match")  // Custom validator, see below
public class ResetPasswordDTO {

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

    @NotBlank(message = "OTP code is required")
    @Pattern(regexp = "\\d{6}", message = "OTP code must be 6 digits")
    private String otpCode;

    @NotBlank(message = "New password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
            message = "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character"
    )
    private String newPassword;

    @NotBlank(message = "Confirm password is required")
    private String confirmPassword;
}

