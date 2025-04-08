package com.teamwork.forexcalculator.user.service;

import com.teamwork.forexcalculator.user.models.User;
import com.teamwork.forexcalculator.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;


    // Register user
    public User registerUser(User user) {
        if (userRepository.findByEmail(user.getEmail()) != null) {
            throw new RuntimeException("Email already exists");
        }

        return user;
    }

    // Find user by email (for authentication)
    public User findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}
