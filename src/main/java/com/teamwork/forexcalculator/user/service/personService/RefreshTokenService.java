/*
package com.teamwork.forexcalculator.user.service.personService;

import com.teamwork.forexcalculator.user.exceptionHandling.TokenRefreshException;
import com.teamwork.forexcalculator.user.models.RefreshToken;
import com.teamwork.forexcalculator.user.repository.RefreshTokenRepository;
import com.teamwork.forexcalculator.user.repository.PersonRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final PersonRepo personRepo;

    @Value("${app.jwt.refreshExpirationMs}")
    private Long refreshTokenDurationMs;

    @Transactional
    public RefreshToken createRefreshToken(Long personId, String tokenValue) {
        // Invalidate any existing tokens
        invalidateAllUserTokens(personId);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setPerson(personRepo.findById(personId).orElseThrow());
        refreshToken.setToken(tokenValue);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException("Refresh token expired");
        }
        return token;
    }

    @Transactional
    public void invalidateToken(String token) {
        refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public void invalidateAllUserTokens(Long personId) {
        refreshTokenRepository.deleteByPersonId(personId);
    }
}*/
