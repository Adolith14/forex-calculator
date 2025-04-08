package com.teamwork.forexcalculator.user.repository;

import com.teamwork.forexcalculator.user.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByEmail(String email);
}
