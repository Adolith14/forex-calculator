package com.teamwork.forexcalculator.user.controller;

import com.teamwork.forexcalculator.user.dto.*;
import com.teamwork.forexcalculator.user.exceptionHandling.*;
import com.teamwork.forexcalculator.user.repository.RefreshTokenRepository;
import com.teamwork.forexcalculator.user.securities.jwt.JwtUtil;
import com.teamwork.forexcalculator.user.service.personService.AuthService;
import com.teamwork.forexcalculator.user.service.personService.TokenBlacklistService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;
    private final TokenBlacklistService tokenBlacklistService;
    private final RefreshTokenRepository refreshTokenRepository;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<String>> register(@Valid @RequestBody RegistrationDTO request) {
        try {
            String response = authService.registerUser(request);
            return ResponseEntity.ok(new ApiResponse<>(true, response, null));
        } catch (DuplicateEmailException | DuplicatePhoneException |
                 PasswordMismatchException e) {
            return ResponseEntity.badRequest().body(new ApiResponse<>(false, null, e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<String>> login(@Valid @RequestBody LoginDTO request) {
        try {
            String response = authService.loginPerson(request);
            return ResponseEntity.ok(new ApiResponse<>(true, response, null));
        } catch (InvalidCredentialsException | AccountNotVerifiedException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(false, null, e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestBody LogoutRequest logoutRequest,
            HttpServletRequest request) {
        // Invalidate access token
        String accessToken = jwtUtil.extractToken(request);
        if (accessToken != null) {
            tokenBlacklistService.blacklistToken(accessToken);
        }

        // Invalidate refresh token if provided
       /* if (logoutRequest != null && logoutRequest.getRefreshToken() != null) {
            refreshTokenService.invalidateToken(logoutRequest.getRefreshToken());
        }*/

        return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "Logout completed successfully"
        ));
    }

    /*@PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
        try {
            String refreshToken = request.getRefreshToken();

            // Verify refresh token
            if (!jwtUtil.validateToken(refreshToken)) {
                throw new TokenRefreshException("Invalid refresh token");
            }

            // Check if refresh token exists in DB
            RefreshToken storedToken = refreshTokenRepository.findByToken(refreshToken)
                    .orElseThrow(() -> new TokenRefreshException("Refresh token not found"));

            // Generate new access token
            String email = jwtUtil.extractEmail(refreshToken);
            String newAccessToken = jwtUtil.generateToken(email);

            return ResponseEntity.ok(Map.of(
                    "accessToken", newAccessToken,
                    "refreshToken", refreshToken
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
        }
    }*/

    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponse<String>> verifyOtp(@Valid @RequestBody LoginOtpVerifyDTO request) {
        try {
            String token = authService.verifyOtpCode(request);
            return ResponseEntity.ok(new ApiResponse<>(true, token, null));
        } catch (InvalidOtpException | ExpiredOtpException e) {
            return ResponseEntity.badRequest().body(new ApiResponse<>(false, null, e.getMessage()));
        }
    }

    @PostMapping("/verify-email")
    public ResponseEntity<ApiResponse<String>> verifyEmail(@Valid @RequestBody EmailVerifyDTO dto) {
        try {
            String response = authService.verifyOtp(dto.getEmail(), dto.getOtpCode());
            return ResponseEntity.ok(new ApiResponse<>(true, response, null));
        } catch (InvalidOtpException | ExpiredOtpException e) {
            return ResponseEntity.badRequest().body(new ApiResponse<>(false, null, e.getMessage()));
        }
    }

    @PostMapping("/verify-phone")
    public ResponseEntity<ApiResponse<String>> verifyPhone(@Valid @RequestBody PhoneVerifyDTO dto) {
        try {
            String response = authService.verifyPhoneNumber(dto.getPhoneNumber(), dto.getOtpCode());
            return ResponseEntity.ok(new ApiResponse<>(true, response, null));
        } catch (InvalidOtpException | ExpiredOtpException e) {
            return ResponseEntity.badRequest().body(new ApiResponse<>(false, null, e.getMessage()));
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<String>> forgotPassword(@Valid @RequestBody ForgotPasswordDTO requestDTO) {
        try {
            String response = authService.forgotPassword(requestDTO);
            return ResponseEntity.ok(new ApiResponse<>(true, response, null));
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>(false, null, e.getMessage()));
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<String>> resetPassword(@Valid @RequestBody ResetPasswordDTO resetDTO) {
        try {
            String response = authService.resetPassword(resetDTO);
            return ResponseEntity.ok(new ApiResponse<>(true, response, null));
        } catch (PasswordMismatchException |
                 InvalidOtpException | ExpiredOtpException e) {
            return ResponseEntity.badRequest().body(new ApiResponse<>(false, null, e.getMessage()));
        }
    }

    @GetMapping("/user/profile")
    public ResponseEntity<ApiResponse<ProfileResponseDTO>> getProfile(@RequestHeader("Authorization") String token) {
        try {
            String email = jwtUtil.extractEmail(token.replace("Bearer ", ""));
            ProfileResponseDTO profile = authService.getProfile(email);
            return ResponseEntity.ok(new ApiResponse<>(true, profile, null));
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>(false, null, e.getMessage()));
        }
    }

    @PutMapping("/user/profile")
    public ResponseEntity<ApiResponse<String>> updateProfile(@Valid @RequestBody UpdateProfileDTO dto,
                                                             Authentication authentication) {
        try {
            String email = authentication.getName();
            String response = authService.updateProfile(dto, email);
            return ResponseEntity.ok(new ApiResponse<>(true, response, null));
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>(false, null, e.getMessage()));
        }
    }

    @PostMapping("/user/profile/avatar")
    public ResponseEntity<ApiResponse<String>> uploadAvatar(@RequestParam("file") MultipartFile file,
                                                            @RequestHeader("Authorization") String token) {
        try {
            String email = jwtUtil.extractEmail(token.replace("Bearer ", ""));
            String response = authService.uploadAvatar(email, file);
            return ResponseEntity.ok(new ApiResponse<>(true, response, null));
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>(false, null, e.getMessage()));
        } catch (FileUploadException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(false, null, e.getMessage()));
        }
    }

    @GetMapping("/user/profile/avatar-image")
    public ResponseEntity<?> getAvatar(@RequestHeader("Authorization") String token) {
        try {
            String email = jwtUtil.extractEmail(token.replace("Bearer ", ""));
            return authService.getAvatarFile(email);
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>(false, null, e.getMessage()));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(false, null, "Failed to retrieve avatar"));
        }
    }

    @PutMapping("/user/profile/change-password")
    public ResponseEntity<ApiResponse<String>> changePassword(@Valid @RequestBody ChangePasswordDTO dto,
                                                              @RequestHeader("Authorization") String token) {
        try {
            String email = jwtUtil.extractEmail(token.replace("Bearer ", ""));
            String response = authService.changePassword(email, dto);
            return ResponseEntity.ok(new ApiResponse<>(true, response, null));
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>(false, null, e.getMessage()));
        } catch (InvalidPasswordException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(false, null, e.getMessage()));
        } catch (WeakPasswordException e) {
            return ResponseEntity.badRequest().body(new ApiResponse<>(false, null, e.getMessage()));
        }
    }
}