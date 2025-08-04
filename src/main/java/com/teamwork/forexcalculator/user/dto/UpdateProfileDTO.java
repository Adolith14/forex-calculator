package com.teamwork.forexcalculator.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UpdateProfileDTO {

    @NotBlank(message = "First name is required")
    @Size(max = 50, message = "First name must be at most 50 characters")
    private String firstName;

    @NotBlank(message = "Surname is required")
    @Size(max = 50, message = "Surname must be at most 50 characters")
    private String surname;

    @NotBlank(message = "Phone number is required")
    @Pattern(
            regexp = "^(?:\\+255|0)?[67]\\d{8}$",
            message = "Phone number must be a valid Tanzania number"
    )
    private String phoneNumber;

    private String preferredLanguage;

    private Boolean darkModeEnabled;
}
