package com.teamwork.forexcalculator.user.service.personService;

import com.teamwork.forexcalculator.user.dto.*;

public interface AuthService {
    String registerUser(RegistrationRequest registrationRequest);
    String loginPerson(LoginRequest loginRequest);
    String verifyOtpCode(OtpVerifyRequest request);
    String verifyOtp(String email, String otpCode);
    String forgotPassword(ForgotPasswordRequestDTO requestDTO);
    String resetPassword(ResetPasswordDTO resetDTO);
}
