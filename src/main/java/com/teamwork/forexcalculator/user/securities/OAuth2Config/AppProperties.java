package com.teamwork.forexcalculator.user.securities.OAuth2Config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "app.oauth2")
public class AppProperties {
    private String oauth2SuccessRedirectUrl;
    private String oauth2FailureRedirectUrl;
    private String defaultSuccessUrl;

}