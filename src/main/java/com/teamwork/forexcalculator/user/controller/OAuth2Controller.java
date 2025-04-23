package com.teamwork.forexcalculator.user.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth/oauth2")
public class OAuth2Controller {

    @GetMapping("/success")
    public ResponseEntity<String> handleGoogleLogin(OAuth2AuthenticationToken token) {
        OAuth2User user = token.getPrincipal();
        String email = user.getAttribute("email");

        // TODO: Check if user exists in DB, create if not, generate JWT
        String jwtToken = generateJwtTokenForUser(email);

        return ResponseEntity.ok(jwtToken);
    }

    private String generateJwtTokenForUser(String email) {
        // Implement JWT generation logic
        return "mock-jwt-for-" + email;
    }
}
