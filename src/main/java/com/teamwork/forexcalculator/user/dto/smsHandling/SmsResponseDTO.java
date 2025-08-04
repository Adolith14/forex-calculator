package com.teamwork.forexcalculator.user.dto.smsHandling;

import lombok.Data;

@Data
public class SmsResponseDTO {

    private String error_code;
    private String description;

    public SmsResponseDTO(String number, String messageReceived) {
        this.error_code = number;
        this.description = messageReceived;
    }
}
