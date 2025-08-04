package com.teamwork.forexcalculator.user.models;

import jakarta.persistence.*;
import lombok.Data;
import java.time.Instant;

@Data
@Entity
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "person_id", referencedColumnName = "id")
    private Person person;

    @Column(nullable = false, unique = true)
    private String token;

    @Column(nullable = false)
    private Instant expiryDate;
}
