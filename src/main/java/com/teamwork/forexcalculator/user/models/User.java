package com.teamwork.forexcalculator.user.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotEmpty
    @Size(min = 3, message = "First name must be at least 3 characters")
    private String firstName;

    @NotEmpty
    @Size(min = 3, message = "Surname must be at least 3 characters")
    private String surname;

    @NotEmpty
    @Email(message = "Email should be valid")
    private String email;

    @NotEmpty
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;

    @Transient
    @NotEmpty(message = "Confirm password must not be empty")
    private String confirmPassword;

    @NotEmpty
    private String role;  // E.g., "USER", "ADMIN"

    public Object getConfirmPassword() {
        return null;
    }

    public CharSequence getPassword() {
        return null;
    }

    public String getEmail() {
        return null;
    }

    public void setPassword(String encode) {

    }

    // Getters and Setters

}
