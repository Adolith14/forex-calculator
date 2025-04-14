package com.teamwork.forexcalculator.user.service.personService;

import com.teamwork.forexcalculator.user.dto.*;
import com.teamwork.forexcalculator.user.models.EmailVerificationToken;
import com.teamwork.forexcalculator.user.models.OtpCode;
import com.teamwork.forexcalculator.user.models.Person;
import com.teamwork.forexcalculator.user.models.Role;
import com.teamwork.forexcalculator.user.repository.EmailVerificationTokenRepository;
import com.teamwork.forexcalculator.user.repository.OtpCodeRepository;
import com.teamwork.forexcalculator.user.repository.PersonRepo;
import com.teamwork.forexcalculator.user.securities.jwt.JwtUtil;
import com.teamwork.forexcalculator.user.service.emailService.EmailService;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final PersonRepo personRepo;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final JwtUtil jwtUtil;
    private final OtpCodeRepository otpCodeRepo;
    private final EmailVerificationTokenRepository emailVerificationTokenRepo;

    @Override
    public String registerUser(RegistrationRequest registrationRequest) {
        if (!registrationRequest.getPassword().equals(registrationRequest.getConfirmPassword())) {
            return "Password do not match";
        }

        if (personRepo.findByEmail(registrationRequest.getEmail()).isPresent()) {
            return "Email already exists";
        }

        Person person = Person.builder()
                .firstName(registrationRequest.getFirstName())
                .surname(registrationRequest.getSurname())
                .email(registrationRequest.getEmail())
                .password(passwordEncoder.encode(registrationRequest.getPassword()))
                .role(Role.USER)
                .verified(false)
                .build();

        personRepo.save(person);

        // Generate OTP and save token
        String otp = String.valueOf(new Random().nextInt(900000) + 100000);

        EmailVerificationToken token = new EmailVerificationToken();
        token.setOtpCode(otp);
        token.setPerson(person);
        token.setExpiryDate(LocalDateTime.now().plusMinutes(15));
        emailVerificationTokenRepo.save(token);

        // Send email
        emailService.sendOtpCode(person.getEmail(), otp);

        return "Registration successful. OTP sent to your email for verification.";
    }

    @Override
    public String loginPerson(LoginRequest loginRequest) {
        Optional<Person> userOpt = personRepo.findByEmail(loginRequest.getEmail());

        if (userOpt.isEmpty())
            return "Invalid credentials";

        Person person = userOpt.get();
        if (!passwordEncoder.matches(loginRequest.getPassword(), person.getPassword())) {
            return "Invalid credentials";
        }

        // Generate 6-digit code
        String otp = String.valueOf(new Random().nextInt(900000) + 100000);

        // Save OTP with expiry
        OtpCode otpCode = new OtpCode();
        otpCode.setCode(otp);
        otpCode.setExpiry(LocalDateTime.now().plusMinutes(5));
        otpCode.setPerson(person);
        otpCodeRepo.save(otpCode);

        // Send OTP
        emailService.sendLoginToken(person.getEmail(), otp);

        return "A login code has been sent to your email.";
    }

    @Override
    public String verifyOtpCode(OtpVerifyRequest request) {
        Optional<OtpCode> otpCodeOpt = otpCodeRepo.findByPerson_Email(request.getEmail());

        if (otpCodeOpt.isEmpty())
            return "Invalid code";

        OtpCode otp = otpCodeOpt.get();

        if (!otp.getCode().equals(request.getCode())) {
            return "Incorrect code";
        }

        if (otp.getExpiry().isBefore(LocalDateTime.now())) {
            return "Code expired";
        }

        // OTP is valid -> generate token
        String token = jwtUtil.generateToken(request.getEmail());

        // Optionally delete OTP
        otpCodeRepo.delete(otp);

        return token;
    }

    @Override
    public String verifyOtp(String email, String otpCode) {
        Optional<EmailVerificationToken> optionalToken = emailVerificationTokenRepo
                .findByPersonEmail(email);

        if (optionalToken.isEmpty()) return "No OTP found for this email";

        EmailVerificationToken token = optionalToken.get();
        if (!token.getOtpCode().equals(otpCode))
            return "Invalid OTP";

        if (token.getExpiryDate().isBefore(LocalDateTime.now()))
            return "OTP expired";

        // Delete token to mark as verified
        emailVerificationTokenRepo.delete(token);
        return "Email verified successfully!";
    }

    @Override
    public String forgotPassword(ForgotPasswordRequestDTO requestDTO) {
        Optional<Person> personOpt = personRepo.findByEmail(requestDTO.getEmail());

        if (personOpt.isEmpty())
            return "User with email not found";

        Person person = personOpt.get();
        String otp = String.valueOf(new Random().nextInt(900000) + 100000);

        Optional<EmailVerificationToken> existingToken = emailVerificationTokenRepo
                .findByPersonEmail(requestDTO.getEmail());
        EmailVerificationToken token = existingToken.orElse(new EmailVerificationToken());
        token.setPerson(person);
        token.setOtpCode(otp);
        token.setExpiryDate(LocalDateTime.now().plusMinutes(10));
        emailVerificationTokenRepo.save(token);

        emailService.sendOtpCode(person.getEmail(), otp);
        return "Reset OTP sent to your email.";
    }

    @Override
    public String resetPassword(ResetPasswordDTO resetDTO) {
        if (!resetDTO.getNewPassword().equals(resetDTO.getConfirmPassword())) {
            return "Passwords do not match";
        }

        Optional<EmailVerificationToken> tokenOpt = emailVerificationTokenRepo
                .findByOtpCode(resetDTO.getOtpCode());
        if (tokenOpt.isEmpty()) return "Invalid OTP";

        EmailVerificationToken token = tokenOpt.get();

        if (!token.getPerson().getEmail().equals(resetDTO.getEmail())) return "Email mismatch";
        if (token.getExpiryDate().isBefore(LocalDateTime.now())) return "OTP has expired";

        Person person = token.getPerson();
        person.setPassword(passwordEncoder.encode(resetDTO.getNewPassword()));
        personRepo.save(person);
        emailVerificationTokenRepo.delete(token);

        return "Password reset successfully.";
    }
}
