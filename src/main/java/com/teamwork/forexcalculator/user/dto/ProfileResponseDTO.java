package com.teamwork.forexcalculator.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ProfileResponseDTO {

    @NotBlank(message = "First name is required")
    @Size(max = 50, message = "First name must be at most 50 characters")
    private String firstName;

    @NotBlank(message = "Surname is required")
    @Size(max = 50, message = "Surname must be at most 50 characters")
    private String surname;

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

    @NotBlank(message = "Phone number is required")
    @Pattern(regexp = "^(?:\\+255|0)?[67]\\d{8}$", message = "Invalid Tanzania phone number")
    private String phoneNumber;

    private String avatarUrl;

    private String preferredLanguage;

    private Boolean darkModeEnabled;
}
