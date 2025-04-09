package com.teamwork.forexcalculator.user.dto;

import lombok.*;

@Data
public class RegistrationRequest {
    private String firstName;
    private String surname;
    private String email;
    private String password;
    private String confirmPassword;


}
