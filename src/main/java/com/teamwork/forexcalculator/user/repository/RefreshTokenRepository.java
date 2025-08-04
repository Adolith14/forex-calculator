package com.teamwork.forexcalculator.user.repository;

import com.teamwork.forexcalculator.user.models.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    void deleteByPersonId(Long personId);
}