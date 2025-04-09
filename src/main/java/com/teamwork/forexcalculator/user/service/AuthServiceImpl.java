package com.teamwork.forexcalculator.user.service;

import com.teamwork.forexcalculator.user.dto.LoginRequest;
import com.teamwork.forexcalculator.user.dto.RegistrationRequest;
import com.teamwork.forexcalculator.user.models.Person;
import com.teamwork.forexcalculator.user.models.Role;
import com.teamwork.forexcalculator.user.repository.PersonRepo;
import com.teamwork.forexcalculator.user.securityConfig.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final PersonRepo personRepo;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final JwtUtil jwtUtil;

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
                .build();

        personRepo.save(person);
        return "Registration successful";
    }

    @Override
    public String loginPerson(LoginRequest loginRequest) {
        Optional<Person> userOpt = personRepo.findByEmail(loginRequest.getEmail());

        if (userOpt.isEmpty()) return "Invalid credentials";

        Person person = userOpt.get();
        if (!passwordEncoder.matches(loginRequest.getPassword(), person.getPassword())) {
            return "Invalid credentials";
        }

        String token = jwtUtil.generateToken(person.getEmail());
        return emailService.sendLoginToken(loginRequest.getEmail(), token);
    }
}
