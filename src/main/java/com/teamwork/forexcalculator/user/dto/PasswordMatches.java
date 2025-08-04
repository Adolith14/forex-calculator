package com.teamwork.forexcalculator.user.dto;

import jakarta.validation.Payload;

public @interface PasswordMatches {
    String message() default "Passwords do not match";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
