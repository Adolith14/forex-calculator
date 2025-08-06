package com.teamwork.forexcalculator.user.service.personService;

import com.google.i18n.phonenumbers.NumberParseException;
import com.teamwork.forexcalculator.user.dto.*;
import com.teamwork.forexcalculator.user.dto.smsHandling.SmsRequestDTO;
import com.teamwork.forexcalculator.user.dto.smsHandling.SmsResponseDTO;
import com.teamwork.forexcalculator.user.exceptionHandling.*;
import com.teamwork.forexcalculator.user.models.*;
import com.teamwork.forexcalculator.user.repository.*;
import com.teamwork.forexcalculator.user.securities.jwt.JwtUtil;
import com.teamwork.forexcalculator.user.service.emailService.EmailService;
import com.teamwork.forexcalculator.user.service.phoneNumberValidator.PhoneNumberValidator;
import com.teamwork.forexcalculator.user.service.s3Service.S3Service;
import com.teamwork.forexcalculator.user.service.smsService.SmsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.net.URI;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final PersonRepo personRepo;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final JwtUtil jwtUtil;
    private final OtpCodeRepository otpCodeRepo;
    private final EmailVerificationTokenRepository emailVerificationTokenRepo;
    private final PhoneVerificationRepository phoneVerificationRepo;
    private final SmsService smsService;
    private final S3Service s3Service;

    private static final int OTP_EXPIRY_MINUTES = 15;
    private static final int LOGIN_OTP_EXPIRY_MINUTES = 5;

    @Override
    public String registerUser(RegistrationDTO registrationDTO) {
        validateRegistration(registrationDTO);

        Person person = buildPersonFromRegistration(registrationDTO);
        personRepo.save(person);

        String otp = generateOtp();
        String maskedOtp = maskOtp(otp);
        saveVerificationTokens(person, maskedOtp);
        sendOtpToAvailableChannels(person, maskedOtp, true);

        return "Registration successful. Verification codes sent to your email and phone number.";
    }
    private String maskOtp(String otp) {
        // Show first 2 and last 2 characters, mask others (e.g., 12****34)
        int length = otp.length();
        if (length <= 4) return "****";

        String start = otp.substring(0, 2);
        String end = otp.substring(length - 2);
        return start + "****" + end;
    }

    private void validateRegistration(RegistrationDTO registrationDTO) {
        // ... existing validations ...

        // Validate international phone number
        if (!PhoneNumberValidator.isValid(registrationDTO.getPhoneNumber(), registrationDTO.getCountryCode())) {
            throw new InvalidPhoneNumberException("Invalid phone number for country: " + registrationDTO.getCountryCode());
        }

        // Convert to E164 format
        try {
            String formattedNumber = PhoneNumberValidator.formatE164(
                    registrationDTO.getPhoneNumber(),
                    registrationDTO.getCountryCode()
            );
            registrationDTO.setPhoneNumber(formattedNumber); // +2348012345678
        } catch (NumberParseException e) {
            throw new InvalidPhoneNumberException("Phone number parsing failed");
        }

        // Check for duplicates with formatted number
        if (personRepo.findByPhoneNumber(registrationDTO.getPhoneNumber()).isPresent()) {
            throw new DuplicatePhoneException("Phone number already exists");
        }
    }

    private Person buildPersonFromRegistration(RegistrationDTO registrationDTO) {
        return Person.builder()
                .firstName(registrationDTO.getFirstName())
                .surname(registrationDTO.getSurname())
                .email(registrationDTO.getEmail())
                .phoneNumber(registrationDTO.getPhoneNumber())
                .password(passwordEncoder.encode(registrationDTO.getPassword()))
                .role(Role.USER)
                .verified(false)
                .emailVerified(false)
                .phoneNumberVerified(false)
                .darkModeEnabled(false)
                .build();
    }

    @Override
    public String loginPerson(LoginDTO loginDTO) {
        Person person = authenticateUser(loginDTO);

        if (!person.isVerified()) {
            String otp = generateOtp();
            String maskedOtp = maskOtp(otp);
            saveVerificationTokens(person, maskedOtp);
            sendOtpToAvailableChannels(person, maskedOtp, true);
            throw new AccountNotVerifiedException("Account not verified. Verification code sent.");
        }

        String loginOtp = generateAndSaveLoginOtp(person);
        String maskedOtp = maskOtp(loginOtp);
        sendOtpToAvailableChannels(person, maskedOtp, false);

        return "Login code has been sent to your registered email/phone.";
    }

    private Person authenticateUser(LoginDTO loginDTO) {
        String identifier = loginDTO.getEmailOrPhoneNumber();

        // If identifier is a phone number
        if (identifier.matches("^\\+?[0-9].*")) {
            try {
                // Parse and format the phone number
                String formattedNumber = PhoneNumberValidator.formatE164(
                        identifier,
                        loginDTO.getCountryCode()
                );
                identifier = formattedNumber;
            } catch (NumberParseException e) {
                throw new InvalidCredentialsException("Invalid phone number format");
            }
        }

        Optional<Person> userOpt = isEmail(identifier)
                ? personRepo.findByEmail(identifier)
                : personRepo.findByPhoneNumber(identifier);

        Person person = userOpt.orElseThrow(() ->
                new InvalidCredentialsException("Invalid credentials"));

        if (!passwordEncoder.matches(loginDTO.getPassword(), person.getPassword())) {
            throw new InvalidCredentialsException("Invalid credentials");
        }

        return person;
    }

    @Override
    public String verifyOtpCode(LoginOtpVerifyDTO request) {
        // 1. Find and validate OTP existence
        OtpCode otp = otpCodeRepo.findByPerson_Email(request.getEmail())
                .orElseThrow(() -> {
                    log.warn("OTP attempt for non-existent email: {}", request.getEmail());
                    return new InvalidOtpException("Invalid code");
                });

        // 2. Check expiration (with timezone awareness)
        if (otp.getExpiry().isBefore(LocalDateTime.now(ZoneId.of("UTC")))) {
            otpCodeRepo.delete(otp);
            log.warn("Expired OTP attempt for email: {}", request.getEmail());
            throw new ExpiredOtpException("OTP expired. Please request a new one.");
        }

        // 3. Validate OTP match (case-insensitive and trim whitespace)
        if (!otp.getCode().trim().equalsIgnoreCase(request.getCode().trim())) {
            log.warn("Invalid OTP attempt for email: {}", request.getEmail());
            throw new InvalidOtpException("The code you entered is incorrect");
        }

        // 4. Generate JWT with additional claims
        Map<String, Object> claims = new HashMap<>();
        claims.put("otpVerified", true);
        claims.put("authTime", Instant.now().getEpochSecond());

        String token = jwtUtil.generateToken(request.getEmail(), claims);

        // 5. Cleanup (with transaction awareness)
        try {
            otpCodeRepo.delete(otp);
            otpCodeRepo.flush();
        } catch (Exception e) {
            log.error("Failed to delete OTP for email: {}", request.getEmail(), e);
        }

        // 6. Audit log
        log.info("Successful OTP verification for email: {}", request.getEmail());

        return token;
    }

    @Override
    public String verifyOtp(String email, String otpCode) {
        EmailVerificationToken token = emailVerificationTokenRepo.findByPersonEmail(email)
                .orElseThrow(() -> new InvalidOtpException("No OTP found for this email"));

        validateOtpToken(token, otpCode);

        Person person = token.getPerson();
        person.setVerified(true);
        person.setEmailVerified(true);
        personRepo.save(person);

        emailVerificationTokenRepo.delete(token);
        return "Email verified successfully!";
    }

    @Override
    public String verifyPhoneNumber(String phoneNumber, String phoneOtp) {
        PhoneNumberVerificationOtp otp = phoneVerificationRepo.findByPhoneNumber(phoneNumber)
                .orElseThrow(() -> new InvalidOtpException("No OTP found for this phone number"));

        validatePhoneOtp(otp, phoneOtp);

        Person person = otp.getPerson();
        person.setVerified(true);
        person.setPhoneNumberVerified(true);
        personRepo.save(person);

        phoneVerificationRepo.delete(otp);

        // Return response that matches gateway format
        return "{\"error_code\":\"200\",\"description\":\"success\"}";
    }

    private void validatePhoneOtp(PhoneNumberVerificationOtp otp, String phoneOtp) {
        if (otp.getPhoneOtp() == null || otp.getExpiryDate() == null) {
            throw new InvalidOtpException("Invalid OTP data");
        }
        if (!otp.getPhoneOtp().trim().equals(phoneOtp.trim())) {
            throw new InvalidOtpException("Invalid OTP");
        }
        if (otp.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new ExpiredOtpException("OTP expired");
        }
    }

    @Override
    public SmsResponseDTO processSmsVerification(SmsRequestDTO request) {
        if (request.getMessage().matches(".*\\b\\d{6}\\b.*")) {
            String otp = extractOtp(request.getMessage());
            try {
                verifyPhoneNumber(request.getMsisdn(), otp);
                return new SmsResponseDTO("200", "success");
            } catch (Exception e) {
                return new SmsResponseDTO("400", e.getMessage());
            }
        }
        return new SmsResponseDTO("200", "Message received");
    }

    private String extractOtp(String message) {
        Pattern pattern = Pattern.compile("\\b\\d{6}\\b");
        Matcher matcher = pattern.matcher(message);
        if (matcher.find()) {
            return matcher.group();
        }
        throw new InvalidOtpException("No valid OTP found in message");
    }

    @Override
    public String forgotPassword(ForgotPasswordDTO requestDTO) {
        Person person = personRepo.findByEmail(requestDTO.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User with email not found"));

        String otp = generateAndSaveEmailVerificationToken(person);
        String maskedOtp = maskOtp(otp);
        emailService.resetPasswordEmail(person.getEmail(), maskedOtp);

        return "Reset OTP sent to your email.";
    }

    @Override
    public String resetPassword(ResetPasswordDTO resetDTO) {
        if (!resetDTO.getNewPassword().equals(resetDTO.getConfirmPassword())) {
            throw new PasswordMismatchException("Passwords do not match");
        }

        EmailVerificationToken token = emailVerificationTokenRepo.findByOtpCode(resetDTO.getOtpCode())
                .orElseThrow(() -> new InvalidOtpException("Invalid OTP"));

        validatePasswordReset(token, resetDTO);

        Person person = token.getPerson();
        person.setPassword(passwordEncoder.encode(resetDTO.getNewPassword()));
        personRepo.save(person);
        emailVerificationTokenRepo.delete(token);

        return "Password reset successfully.";
    }

    private void validatePasswordReset(EmailVerificationToken token, ResetPasswordDTO resetDTO) {
        if (!token.getPerson().getEmail().equals(resetDTO.getEmail())) {
            throw new InvalidOtpException("Email mismatch");
        }
        if (token.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new ExpiredOtpException("OTP has expired");
        }
        if (isStrongPassword(resetDTO.getNewPassword())) {
            throw new WeakPasswordException(
                    "New password must contain at least one uppercase letter, " +
                            "one lowercase letter, one digit, and one special character"
            );
        }
    }

    @Override
    public String updateProfile(UpdateProfileDTO dto, String email) {
        Person person = personRepo.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        person.setFirstName(dto.getFirstName());
        person.setSurname(dto.getSurname());
        person.setPhoneNumber(dto.getPhoneNumber());
        person.setDarkModeEnabled(dto.getDarkModeEnabled());

        personRepo.save(person);
        return "Profile updated successfully.";
    }

    @Override
    public CompletableFuture<String> uploadAvatar(String email, MultipartFile file) {
        if (file.isEmpty()) {
            return CompletableFuture.failedFuture(new FileUploadException("File cannot be empty"));
        }

        return personRepo.findByEmail(email)
                .map(person -> s3Service.uploadFileAsync(file)
                        .thenCompose(avatarUrl -> {
                            person.setAvatarUrl(avatarUrl);
                            personRepo.save(person);
                            return CompletableFuture.completedFuture("Avatar uploaded successfully");
                        }))
                .orElse(CompletableFuture.failedFuture(new UserNotFoundException("User not found")));
    }

    @Override
    public String getAvatarUrl(String email) throws UserNotFoundException {
        Person person = personRepo.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (person.getAvatarUrl() == null) {
            throw new FileUploadException("Avatar not found");
        }
        return person.getAvatarUrl(); // Returns full S3 URL
    }

    @Override
    public String changePassword(String email, ChangePasswordDTO dto) {
        Person person = personRepo.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        validatePasswordChange(person, dto);
        person.setPassword(passwordEncoder.encode(dto.getNewPassword()));
        personRepo.save(person);

        return "Password changed successfully.";
    }

    private void validatePasswordChange(Person person, ChangePasswordDTO dto) {
        if (!passwordEncoder.matches(dto.getOldPassword(), person.getPassword())) {
            throw new InvalidPasswordException("Current password is incorrect");
        }
        if (!dto.getNewPassword().equals(dto.getConfirmPassword())) {
            throw new PasswordMismatchException("New password and confirm password do not match");
        }
        if (isStrongPassword(dto.getNewPassword())) {
            throw new WeakPasswordException(
                    "New password must contain at least one uppercase letter, " +
                            "one lowercase letter, one digit, and one special character"
            );
        }
    }

    @Override
    public ResponseEntity<Resource> getAvatarFile(String email) {
        Person person = personRepo.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (person.getAvatarUrl() == null) {
            throw new FileUploadException("Avatar not found");
        }

        // Redirect to S3 URL (or proxy the file if needed)
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(person.getAvatarUrl()))
                .build();
    }

    @Override
    public ProfileResponseDTO getProfile(String email) {
        Person person = personRepo.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        return ProfileResponseDTO.builder()
                .firstName(person.getFirstName())
                .surname(person.getSurname())
                .email(person.getEmail())
                .phoneNumber(person.getPhoneNumber())
                .avatarUrl(person.getAvatarUrl() != null ?
                        "/api/auth/user/profile/avatar-image" : null)
                .darkModeEnabled(person.isDarkModeEnabled())
                .build();
    }

    // Internal helper methods

    private String generateOtp() {
        return String.valueOf(new Random().nextInt(900000) + 100000);
    }

    private void saveVerificationTokens(Person person, String otp) {
        if (person.getEmail() != null) {
            EmailVerificationToken emailToken = new EmailVerificationToken();
            emailToken.setOtpCode(otp);
            emailToken.setPerson(person);
            emailToken.setExpiryDate(LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES));
            emailVerificationTokenRepo.save(emailToken);
        }

        if (person.getPhoneNumber() != null) {
            PhoneNumberVerificationOtp phoneToken = new PhoneNumberVerificationOtp();
            phoneToken.setPhoneOtp(otp);
            phoneToken.setPerson(person);
            phoneToken.setExpiryDate(LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES));
            phoneVerificationRepo.save(phoneToken);
        }
    }

    private String generateAndSaveLoginOtp(Person person) {
        String otp = generateOtp();
        String maskedOtp = maskOtp(otp);
        OtpCode code = new OtpCode();
        code.setCode(maskedOtp);
        code.setPerson(person);
        code.setExpiry(LocalDateTime.now().plusMinutes(LOGIN_OTP_EXPIRY_MINUTES));
        otpCodeRepo.save(code);
        return maskedOtp;
    }

    private String generateAndSaveEmailVerificationToken(Person person) {
        String otp = generateOtp();
        String maskedOtp = maskOtp(otp);
        Optional<EmailVerificationToken> existing = emailVerificationTokenRepo.findByPersonEmail(person.getEmail());
        EmailVerificationToken token = existing.orElse(new EmailVerificationToken());
        token.setPerson(person);
        token.setOtpCode(maskedOtp);
        token.setExpiryDate(LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES));
        emailVerificationTokenRepo.save(token);
        return maskedOtp;
    }

    @Async
    public void sendOtpToAvailableChannels(Person person, String otp, boolean isVerification) {
        // Email channel (unchanged)
        if (person.getEmail() != null) {
            CompletableFuture.runAsync(() -> {
                try {
                    if (isVerification) {
                        emailService.sendOtpCode(person.getEmail(), otp);
                    } else {
                        emailService.sendLoginToken(person.getEmail(), otp);
                    }
                } catch (Exception e) {
                    log.error("Failed to send email to {}: {}", person.getEmail(), e.getMessage());
                }
            });
        }

        // SMS channel (updated with international support)
        if (person.getPhoneNumber() != null && person.getCountryCode() != null) {
            CompletableFuture.runAsync(() -> {
                try {
                    if (isVerification) {
                        smsService.sendOtpCode(
                                person.getPhoneNumber(),
                                person.getCountryCode(),
                                otp
                        );
                    } else {
                        smsService.sendLoginToken(
                                person.getPhoneNumber(),
                                person.getCountryCode(),
                                otp
                        );
                    }
                    log.info("SMS OTP sent to {} ({})",
                            person.getPhoneNumber(),
                            person.getCountryCode());
                } catch (InvalidPhoneNumberException e) {
                    log.error("Invalid phone format for {}: {}",
                            person.getPhoneNumber(), e.getMessage());
                } catch (Exception e) {
                    log.error("Failed to send SMS to {}: {}",
                            person.getPhoneNumber(), e.getMessage());
                }
            });
        }
    }

    private boolean isEmail(String identifier) {
        return identifier != null && identifier.contains("@");
    }

    private boolean isStrongPassword(String password) {
        if (password == null)
            return false;

        String pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$";
        return password.matches(pattern);
    }

    private void validateOtpToken(EmailVerificationToken token, String otpCode) {
        if (token.getOtpCode() == null || token.getExpiryDate() == null) {
            throw new InvalidOtpException("Invalid OTP data");
        }
        if (!token.getOtpCode().equals(otpCode)) {
            throw new InvalidOtpException("Invalid OTP code");
        }
        if (token.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new ExpiredOtpException("OTP has expired");
        }
    }

}