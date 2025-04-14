package com.teamwork.forexcalculator.user.models;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
public class EmailVerificationToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String otpCode;

    @OneToOne
    private Person person;

    private LocalDateTime expiryDate;
}
