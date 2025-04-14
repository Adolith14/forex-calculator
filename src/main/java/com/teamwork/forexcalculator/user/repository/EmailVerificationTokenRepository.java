package com.teamwork.forexcalculator.user.repository;


import com.teamwork.forexcalculator.user.models.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {
    Optional<EmailVerificationToken> findByPersonEmail(String email);

    Optional<EmailVerificationToken> findByOtpCode(String otpCode);
}
