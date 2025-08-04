package com.teamwork.forexcalculator.user.dto.smsHandling;

import lombok.Data;

@Data
public class SmsRequestDTO {
    private String message;
    private String msisdn;
    private String channel;
    private String shortcode;
    private String reference;
    private boolean request_dlr;
    private String username;
    private String password;
}
