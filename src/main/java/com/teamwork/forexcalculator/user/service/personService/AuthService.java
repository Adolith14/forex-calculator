package com.teamwork.forexcalculator.user.service.personService;

import com.teamwork.forexcalculator.user.dto.*;

public interface AuthService {
    String registerUser(RegistrationDTO registrationRequest);
    String loginPerson(LoginDTO loginRequest);
    String verifyOtpCode(LoginOtpVerifyDTO request);
    String verifyOtp(String email, String otpCode);
    String forgotPassword(ForgotPasswordDTO requestDTO);
    String resetPassword(ResetPasswordDTO resetDTO);
}
