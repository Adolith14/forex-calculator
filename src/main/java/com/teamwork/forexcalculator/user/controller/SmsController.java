package com.teamwork.forexcalculator.user.controller;

import com.teamwork.forexcalculator.user.dto.smsHandling.SmsRequestDTO;
import com.teamwork.forexcalculator.user.dto.smsHandling.SmsResponseDTO;
import com.teamwork.forexcalculator.user.service.personService.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/sms")
@RequiredArgsConstructor
public class SmsController {
    private final AuthService authService;

    @PostMapping("/process")
    public ResponseEntity<SmsResponseDTO> processSms(@RequestBody SmsRequestDTO request) {
        SmsResponseDTO response = authService.processSmsVerification(request);
        return ResponseEntity.ok(response);
    }
}