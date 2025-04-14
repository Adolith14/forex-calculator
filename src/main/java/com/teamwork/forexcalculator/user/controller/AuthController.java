package com.teamwork.forexcalculator.user.controller;

import com.teamwork.forexcalculator.user.dto.*;
import com.teamwork.forexcalculator.user.service.personService.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegistrationRequest request) {
        return ResponseEntity.ok(authService.registerUser(request));
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.loginPerson(request));
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<String> verifyOtp(@RequestBody OtpVerifyRequest request) {
        return ResponseEntity.ok(authService.verifyOtpCode(request));
    }

    @PostMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestBody OtpVerifyDto dto) {
        return ResponseEntity.ok(authService.verifyOtp(dto.getEmail(), dto.getOtpCode()));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody ForgotPasswordRequestDTO requestDTO) {
        return ResponseEntity.ok(authService.forgotPassword(requestDTO));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordDTO resetDTO) {
        return ResponseEntity.ok(authService.resetPassword(resetDTO));
    }
}
