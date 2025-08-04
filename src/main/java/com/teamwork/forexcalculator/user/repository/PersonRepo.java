package com.teamwork.forexcalculator.user.repository;

import com.teamwork.forexcalculator.user.models.Person;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PersonRepo extends JpaRepository<Person, Long> {
    Optional<Person> findByEmail(String email);

    Optional<Person> findByPhoneNumber(String identifier);
}
