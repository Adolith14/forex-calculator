package com.teamwork.forexcalculator.user.service.phoneNumberValidator;

import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CountryCodeService {

    public List<Country> getSupportedCountries() {
        return List.of(
                new Country("TZ", "Tanzania", "+255"),
                new Country("US", "United States", "+1"),
                new Country("NG", "Nigeria", "+234"),
                new Country("GB", "United Kingdom", "+44")
        );
    }

    public record Country(String code, String name, String dialCode) {}
}