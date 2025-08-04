package com.teamwork.forexcalculator.user.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data

public class PhoneNumberVerificationOtp {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String phoneOtp;
    private String phoneNumber;
    private LocalDateTime expiryDate;

    @OneToOne
    private Person person;
}
