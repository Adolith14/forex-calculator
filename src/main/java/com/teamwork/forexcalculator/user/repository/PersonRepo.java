package com.teamwork.forexcalculator.user.repository;

import com.teamwork.forexcalculator.user.models.Person;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PersonRepo extends JpaRepository<Person, Long> {
    Optional<Person> findByEmail(String email);
}
