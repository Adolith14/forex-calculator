package com.teamwork.forexcalculator.user.service.smsService;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SmsGatewayConfig {

    @Bean
    @ConfigurationProperties(prefix = "sms.gateway")
    public SmsGatewayProperties smsGatewayProperties() {
        return new SmsGatewayProperties();
    }

    @Data
    public static class SmsGatewayProperties {
        private boolean enabled;
        private String url;
        private String username;
        private String password;
        private String senderId;
    }
}