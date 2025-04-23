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
    public String registerUser(RegistrationDTO registrationDTO) {
        if (!registrationDTO.getPassword().equals(registrationDTO.getConfirmPassword())) {
            return "Password do not match";
        }

        if (personRepo.findByEmail(registrationDTO.getEmail()).isPresent()) {
            return "Email already exists";
        }

        Person person = Person.builder()
                .firstName(registrationDTO.getFirstName())
                .surname(registrationDTO.getSurname())
                .email(registrationDTO.getEmail())
                .password(passwordEncoder.encode(registrationDTO.getPassword()))
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

        // Build link for testing
        String verificationLink = "http://localhost:8080/api/auth/verify?email="
                + person.getEmail() + "&otp=" + otp;

        return "Registration successful. OTP sent to your email for verification." +
                "\nVerification Link (for testing): " + verificationLink;
    }

    @Override
    public String loginPerson(LoginDTO loginDTO) {
        Optional<Person> userOpt = personRepo.findByEmail(loginDTO.getEmail());

        if (userOpt.isEmpty())
            return "Invalid credentials";

        Person person = userOpt.get();
        if (!passwordEncoder.matches(loginDTO.getPassword(), person.getPassword())) {
            return "Invalid credentials";
        }

        //Check if email is not verified
        if (!person.isVerified()) {
            //Fetch or regenerate the email verification OTP
            String otp = generateAndSaveEmailVerificationToken(person);

            //Resend email verification link
            emailService.sendOtpCode(person.getEmail(), otp);

            //Return response with verification link
            return "Email not verified. Please verify your email before logging in.\n\n"
                    + "A new OTP has been sent to your email.\n"
                    + "Click to verify: http://localhost:8080/api/auth/verify-email?email="
                    + person.getEmail() + "&otp=" + otp;
        }

        // Generate and save OTP for login
        String otp = generateAndSaveLoginOtp(person);
        emailService.sendLoginToken(person.getEmail(), otp);

        // Build link for testing
        String verificationLink = "http://localhost:8080/api/auth/verify-login?email="
                + person.getEmail() + "&otp=" + otp;

        return "A login code has been sent to your email." +
                "\nLogin Verification Link (for testing): " + verificationLink;
    }

    private String generateAndSaveLoginOtp(Person person) {
        String otp = String.valueOf(new Random().nextInt(900000) + 100000);

        OtpCode otpCode = new OtpCode();
        otpCode.setCode(otp);
        otpCode.setExpiry(LocalDateTime.now().plusMinutes(5));
        otpCode.setPerson(person);

        otpCodeRepo.save(otpCode);
        return otp;
    }

    private String generateAndSaveEmailVerificationToken (Person person) {
        String otp = String.valueOf(new Random().nextInt(900000) + 100000);

        Optional<EmailVerificationToken> existingToken = emailVerificationTokenRepo
                .findByPersonEmail(person.getEmail());
        EmailVerificationToken token = existingToken.orElse(new EmailVerificationToken());
        token.setPerson(person);
        token.setOtpCode(otp);
        token.setExpiryDate(LocalDateTime.now().plusMinutes(60));

        emailVerificationTokenRepo.save(token);

        return otp;
    }



    @Override
    public String verifyOtpCode(LoginOtpVerifyDTO request) {
        //otp code for login verification

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
        //otp code for email verification
        System.out.println("Verifying OTP for email: " + email + ", OTP: " + otpCode);

        Optional<EmailVerificationToken> optionalToken = emailVerificationTokenRepo
                .findByPersonEmail(email);

        if (optionalToken.isEmpty())
            return "No OTP found for this email";

        EmailVerificationToken token = optionalToken.get();

        if (token.getOtpCode() == null || token.getExpiryDate() == null)
            return "Invalid OTP data";

        if (!token.getOtpCode().trim().equals(otpCode.trim()))
            return "Invalid OTP";

        if (token.getExpiryDate().isBefore(LocalDateTime.now()))
            return "OTP expired";

        // Mark user as verified
        Person person = token.getPerson();
        person.setVerified(true);
        personRepo.save(person);

        // Delete the token to prevent reuse
        emailVerificationTokenRepo.delete(token);

        return "Email verified successfully!";
    }

    @Override
    public String forgotPassword(ForgotPasswordDTO requestDTO) {
        Optional<Person> personOpt = personRepo.findByEmail(requestDTO.getEmail());

        if (personOpt.isEmpty())
            return "User with email not found";

        Person person = personOpt.get();

        // Generate or update OTP for password reset
        String otp = generateAndSaveEmailVerificationToken(person);
        emailService.resetPasswordEmail(person.getEmail(), otp);

        return "Reset OTP sent to your email.\n"
                + "Click to verify: http://localhost:8080/api/auth/verify-email?email="
                + person.getEmail() + "&otp=" + otp;
    }

    @Override
    public String resetPassword(ResetPasswordDTO resetDTO) {
        if (!resetDTO.getNewPassword().equals(resetDTO.getConfirmPassword())) {
            return "Passwords do not match";
        }

        Optional<EmailVerificationToken> tokenOpt = emailVerificationTokenRepo
                .findByOtpCode(resetDTO.getOtpCode());
        if (tokenOpt.isEmpty())
            return "Invalid OTP";

        EmailVerificationToken token = tokenOpt.get();

        if (!token.getPerson().getEmail().equals(resetDTO.getEmail()))
            return "Email mismatch";

        if (token.getExpiryDate().isBefore(LocalDateTime.now()))
            return "OTP has expired";

        Person person = token.getPerson();
        person.setPassword(passwordEncoder.encode(resetDTO.getNewPassword()));
        personRepo.save(person);
        emailVerificationTokenRepo.delete(token);

        return "Password reset successfully.";
    }
}
