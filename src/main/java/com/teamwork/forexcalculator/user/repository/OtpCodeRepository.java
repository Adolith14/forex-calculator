package com.teamwork.forexcalculator.user.repository;

import com.teamwork.forexcalculator.user.models.OtpCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OtpCodeRepository extends JpaRepository<OtpCode, Long> {
    Optional<OtpCode> findByPerson_Email(String email);
}
