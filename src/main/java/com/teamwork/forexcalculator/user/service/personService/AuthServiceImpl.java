package com.teamwork.forexcalculator.user.service.personService;

import com.teamwork.forexcalculator.user.dto.*;
import com.teamwork.forexcalculator.user.exceptionHandling.*;
import com.teamwork.forexcalculator.user.models.*;
import com.teamwork.forexcalculator.user.repository.*;
import com.teamwork.forexcalculator.user.securities.jwt.JwtUtil;
import com.teamwork.forexcalculator.user.service.emailService.EmailService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;

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

    private static final int OTP_EXPIRY_MINUTES = 15;
    private static final int LOGIN_OTP_EXPIRY_MINUTES = 5;

    @Override
    public String registerUser(RegistrationDTO registrationDTO) {
        validateRegistration(registrationDTO);

        Person person = buildPersonFromRegistration(registrationDTO);
        personRepo.save(person);

        String otp = generateOtp();
        saveVerificationTokens(person, otp);
        sendOtpToAvailableChannels(person, otp, true);

        return "Registration successful. Verification codes sent to your email and phone number.";
    }

    private void validateRegistration(RegistrationDTO registrationDTO) {
        if (!registrationDTO.getPassword().equals(registrationDTO.getConfirmPassword())) {
            throw new PasswordMismatchException("Passwords do not match");
        }

        if (personRepo.findByEmail(registrationDTO.getEmail()).isPresent()) {
            throw new DuplicateEmailException("Email already exists");
        }

        if (personRepo.findByPhoneNumber(registrationDTO.getPhoneNumber()).isPresent()) {
            throw new DuplicatePhoneException("Phone number already exists");
        }

        if (isStrongPassword(registrationDTO.getPassword())) {
            throw new WeakPasswordException(
                    "Password must contain at least one uppercase letter, " +
                            "one lowercase letter, one digit, and one special character"
            );
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
            saveVerificationTokens(person, otp);
            sendOtpToAvailableChannels(person, otp, true);
            throw new AccountNotVerifiedException("Account not verified. Verification code sent.");
        }

        String loginOtp = generateAndSaveLoginOtp(person);
        sendOtpToAvailableChannels(person, loginOtp, false);

        return "Login code has been sent to your registered email/phone.";
    }

    private Person authenticateUser(LoginDTO loginDTO) {
        String identifier = loginDTO.getEmailOrPhoneNumber();
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
        OtpCode otp = otpCodeRepo.findByPerson_Email(request.getEmail())
                .orElseThrow(() -> new InvalidOtpException("Invalid code"));

        String token = jwtUtil.generateToken(request.getEmail());
        otpCodeRepo.delete(otp);

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
        return "Phone number verified successfully!";
    }

    private void validateOtpToken(EmailVerificationToken token, String otpCode) {
        if (token.getOtpCode() == null || token.getExpiryDate() == null) {
            throw new InvalidOtpException("Invalid OTP data");
        }
        if (!token.getOtpCode().trim().equals(otpCode.trim())) {
            throw new InvalidOtpException("Invalid OTP");
        }
        if (token.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new ExpiredOtpException("OTP expired");
        }
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
    public String forgotPassword(ForgotPasswordDTO requestDTO) {
        Person person = personRepo.findByEmail(requestDTO.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User with email not found"));

        String otp = generateAndSaveEmailVerificationToken(person);
        emailService.resetPasswordEmail(person.getEmail(), otp);

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
    public String uploadAvatar(String email, MultipartFile file) {
        if (file.isEmpty()) {
            throw new FileUploadException("File cannot be empty");
        }

        Person person = personRepo.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        try {
            String filename = UUID.randomUUID() + "_" + file.getOriginalFilename();
            Path path = Paths.get("src/main/resources/uploads/" + filename);
            Files.copy(file.getInputStream(), path, StandardCopyOption.REPLACE_EXISTING);

            person.setAvatarUrl(filename);
            personRepo.save(person);
            return "Avatar uploaded successfully.";
        } catch (IOException e) {
            throw new FileUploadException("Failed to upload avatar: " + e.getMessage());
        }
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
    public ResponseEntity<Resource> getAvatarFile(String email) throws IOException {
        Person person = personRepo.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (person.getAvatarUrl() == null) {
            throw new FileUploadException("Avatar not found");
        }

        Path path = Paths.get("src/main/resources/uploads/" + person.getAvatarUrl());
        Resource resource = new UrlResource(path.toUri());

        if (!resource.exists() || !resource.isReadable()) {
            throw new FileUploadException("Could not read avatar file");
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, Files.probeContentType(path))
                .body(resource);
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

    // --------------------
    // Internal helper methods
    // --------------------

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
        OtpCode code = new OtpCode();
        code.setCode(otp);
        code.setPerson(person);
        code.setExpiry(LocalDateTime.now().plusMinutes(LOGIN_OTP_EXPIRY_MINUTES));
        otpCodeRepo.save(code);
        return otp;
    }

    private String generateAndSaveEmailVerificationToken(Person person) {
        String otp = generateOtp();
        Optional<EmailVerificationToken> existing = emailVerificationTokenRepo.findByPersonEmail(person.getEmail());
        EmailVerificationToken token = existing.orElse(new EmailVerificationToken());
        token.setPerson(person);
        token.setOtpCode(otp);
        token.setExpiryDate(LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES));
        emailVerificationTokenRepo.save(token);
        return otp;
    }

    private void sendOtpToAvailableChannels(Person person, String otp, boolean isVerification) {
        if (person.getEmail() != null) {
            if (isVerification) emailService.sendOtpCode(person.getEmail(), otp);
            else emailService.sendLoginToken(person.getEmail(), otp);
        }
        // Uncomment when SMS service is available
        /*if (person.getPhoneNumber() != null) {
            if (isVerification) smsService.sendOtpCode(person.getPhoneNumber(), otp);
            else smsService.sendLoginToken(person.getPhoneNumber(), otp);
        }*/
    }

    private boolean isEmail(String identifier) {
        return identifier != null && identifier.contains("@");
    }

    private boolean isStrongPassword(String password) {
        String pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$";
        return password == null && !password.matches(pattern);
    }
}