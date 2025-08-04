package com.teamwork.forexcalculator.user.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "users")
public class Person {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String firstName;
    private String surname;
    private String email;
    private String phoneNumber;
    private String password;

    @Column(nullable = false)
    private boolean verified = false;

    @Column(nullable = false)
    private boolean emailVerified = false;

    @Column(nullable = false)
    private boolean phoneNumberVerified = false;

    @Enumerated(EnumType.STRING)
    private Role role = Role.USER;

    @Column(columnDefinition = "TEXT")
    private String avatarUrl;

    private boolean darkModeEnabled;

}
