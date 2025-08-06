package com.teamwork.forexcalculator.user.service.personService;

import com.teamwork.forexcalculator.user.dto.*;
import com.teamwork.forexcalculator.user.dto.smsHandling.SmsRequestDTO;
import com.teamwork.forexcalculator.user.dto.smsHandling.SmsResponseDTO;
import com.teamwork.forexcalculator.user.exceptionHandling.UserNotFoundException;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

public interface AuthService {
    String registerUser(RegistrationDTO registrationRequest);
    String loginPerson(LoginDTO loginRequest);

    String verifyOtpCode(LoginOtpVerifyDTO request);
    String verifyOtp(String email, String otpCode);

    String verifyPhoneNumber(String phoneNumber, String phoneOtp);
    SmsResponseDTO processSmsVerification(SmsRequestDTO request);

    String forgotPassword(ForgotPasswordDTO requestDTO);

    String resetPassword(ResetPasswordDTO resetDTO);
    String updateProfile(UpdateProfileDTO dto, String email);


    CompletableFuture<String> uploadAvatar(String email, MultipartFile file);
    String getAvatarUrl(String email) throws UserNotFoundException;
    String changePassword(String email, ChangePasswordDTO dto);

    ResponseEntity<Resource> getAvatarFile(String email);
    ProfileResponseDTO getProfile(String email);

}
