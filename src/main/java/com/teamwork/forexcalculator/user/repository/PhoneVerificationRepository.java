package com.teamwork.forexcalculator.user.repository;

import com.teamwork.forexcalculator.user.models.PhoneNumberVerificationOtp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PhoneVerificationRepository extends JpaRepository<PhoneNumberVerificationOtp, Long> {
    Optional<PhoneNumberVerificationOtp> findByPhoneNumber(String phoneNumber);
}
