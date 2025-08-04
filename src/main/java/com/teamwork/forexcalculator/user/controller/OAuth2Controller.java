package com.teamwork.forexcalculator.user.controller;

import com.teamwork.forexcalculator.user.securities.OAuth2Config.AppProperties;
import com.teamwork.forexcalculator.user.securities.jwt.JwtUtil;
import com.teamwork.forexcalculator.user.securities.OAuth2Config.CustomOAuth2User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth/oauth2/google")
@RequiredArgsConstructor
public class OAuth2Controller {

    private final JwtUtil jwtUtil;
    private final AppProperties appProperties;

    /**
     * Handles successful Google OAuth2 redirect (GET)
     * Redirects to frontend with JWT token
     */
    @GetMapping("/success")
    public String oauth2SuccessRedirect(@AuthenticationPrincipal CustomOAuth2User oauth2User) {
        String jwtToken = jwtUtil.generateToken(oauth2User.getPerson().getEmail());
        return "redirect:" + appProperties.getOauth2SuccessRedirectUrl() +
                "?token=" + jwtToken +
                "&email=" + oauth2User.getPerson().getEmail();
    }

    /**
     * Handles direct token exchange (POST)
     * Returns JWT token as JSON for API clients
     */
    @PostMapping("/callback")
    public ResponseEntity<Map<String, String>> oauth2Callback(
            @AuthenticationPrincipal CustomOAuth2User oauth2User) {

        String jwtToken = jwtUtil.generateToken(oauth2User.getPerson().getEmail());

        return ResponseEntity.ok(Map.of(
                "token", jwtToken,
                "email", oauth2User.getPerson().getEmail(),
                "message", "Authentication successful"
        ));
    }

    /**
     * Error handler for OAuth2 failures
     */
    @GetMapping("/failure")
    public ResponseEntity<Map<String, String>> oauth2Failure(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "error_description", required = false) String errorDescription) {

        return ResponseEntity.badRequest().body(Map.of(
                "error", error != null ? error : "unknown_error",
                "error_description", errorDescription != null ? errorDescription : "Authentication failed"
        ));
    }
}