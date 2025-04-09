package com.teamwork.forexcalculator.user.service;

import com.teamwork.forexcalculator.user.dto.LoginRequest;
import com.teamwork.forexcalculator.user.dto.RegistrationRequest;

public interface AuthService {
    String registerUser(RegistrationRequest registrationRequest);
    String loginPerson(LoginRequest loginRequest);
}
