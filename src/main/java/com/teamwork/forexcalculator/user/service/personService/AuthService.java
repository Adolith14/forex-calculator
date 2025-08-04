package com.teamwork.forexcalculator.user.service.personService;

import com.teamwork.forexcalculator.user.dto.*;
import com.teamwork.forexcalculator.user.dto.smsHandling.SmsRequestDTO;
import com.teamwork.forexcalculator.user.dto.smsHandling.SmsResponseDTO;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

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

    String uploadAvatar(String email, MultipartFile file);
    String changePassword(String email, ChangePasswordDTO dto);

    ResponseEntity<Resource> getAvatarFile(String email) throws IOException;
    ProfileResponseDTO getProfile(String email);

}
