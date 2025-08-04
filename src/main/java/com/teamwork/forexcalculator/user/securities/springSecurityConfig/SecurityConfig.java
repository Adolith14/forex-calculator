package com.teamwork.forexcalculator.user.securities.springSecurityConfig;

import com.teamwork.forexcalculator.user.models.RefreshToken;
import com.teamwork.forexcalculator.user.repository.PersonRepo;
import com.teamwork.forexcalculator.user.securities.OAuth2Config.AppProperties;
import com.teamwork.forexcalculator.user.securities.OAuth2Config.CustomOAuth2User;
import com.teamwork.forexcalculator.user.securities.OAuth2Config.CustomOAuth2UserService;
import com.teamwork.forexcalculator.user.securities.jwt.JwtUtil;
//import com.teamwork.forexcalculator.user.service.personService.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;
    private final JwtUtil jwtUtil;
    private final AppProperties appProperties;
    private final PersonRepo personRepo;
    /*private final RefreshTokenService refreshTokenService;*/

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String googleClientSecret;


    @Value("${cors.allowed-origins:}")
    private List<String> allowedOrigins;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/auth/register",
                                "/api/auth/login",
                                "/api/auth/verify-otp",
                                "/api/auth/verify-email",
                                "/api/auth/verify-phone",
                                "/api/auth/forgot-password",
                                "/api/auth/reset-password",
                                "/oauth2/**")
                        .permitAll()
                        .requestMatchers("/api/auth/**").authenticated()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .successHandler((request, response, authentication) -> {
                            CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();

                            // Generate tokens
                            String accessToken = jwtUtil.generateToken(oauthUser.getPerson().getEmail());
                            String refreshToken = jwtUtil.generateRefreshToken(oauthUser.getPerson());

                            // Save refresh token to database
/*
                            RefreshToken refreshTokenEntity = refreshTokenService.createRefreshToken(
                                    oauthUser.getPerson().getId(),
                                    refreshToken
                            );
*/

                            // Redirect with tokens
                            response.sendRedirect(appProperties.getOauth2SuccessRedirectUrl() +
                                    "?token=" + accessToken +
                                    "&refreshToken=" + refreshToken);
                        })
                        .failureHandler((request, response, exception) -> {
                            response.sendRedirect(appProperties.getOauth2FailureRedirectUrl() +
                                    "?error=" + exception.getMessage());
                        })
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Set default development origins if none configured
        if (allowedOrigins == null || allowedOrigins.isEmpty()) {
            configuration.setAllowedOrigins(Arrays.asList(
                    "http://localhost:3000",    // React/Vite default
                    "http://127.0.0.1:3000",    // Alternative localhost
                    "http://localhost:8081"     // Common alternative frontend port
            ));
        } else {
            configuration.setAllowedOrigins(allowedOrigins);
        }

        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setExposedHeaders(Arrays.asList("Authorization", "content-type"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L); // 1 hour cache for CORS preflight

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public CustomOAuth2UserService customOAuth2UserService() {
        return new CustomOAuth2UserService(personRepo);
    }
}