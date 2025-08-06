package com.teamwork.forexcalculator.user.securities.jwt;

import com.teamwork.forexcalculator.user.models.Person;
import com.teamwork.forexcalculator.user.repository.PersonRepo;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.Map;

@Component
public class JwtUtil {
    private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private final PersonRepo personRepo;

    @Value("${app.jwt.accessTokenExpirationMs:3600000}") // 1 hour default
    private long accessTokenExpirationMs;

    @Value("${app.jwt.refreshTokenExpirationMs:86400000}") // 24 hours default
    private String refreshTokenExpirationMs;

    public JwtUtil(PersonRepo personRepo) {
        this.personRepo = personRepo;
    }

    // Extract JWT from Authorization header
    public String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }

    public String generateToken(String email) {
        Person person = personRepo.findByEmail(email).orElseThrow();

        return Jwts.builder()
                .setSubject(email)
                .claim("userId", person.getId())
                .claim("verified", person.isVerified())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()+ accessTokenExpirationMs))
                .signWith(key)
                .compact();
    }
    public String generateToken(String email, Map<String, Object> claims) {
        claims.put("sub", email); // Ensure subject is set

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpirationMs))
                .signWith(key)
                .compact();
    }

    public String extractEmail(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    public String generateRefreshToken(Person person) {
        return Jwts.builder()
                .setSubject(person.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpirationMs))
                .signWith(key)
                .compact();
    }

    // Additional method to get expiration date from token
    public Date getExpirationDateFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
    }

    // Method to check if token is expired
    public boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }
}