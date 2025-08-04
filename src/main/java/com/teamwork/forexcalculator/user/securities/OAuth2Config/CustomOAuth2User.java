package com.teamwork.forexcalculator.user.securities.OAuth2Config;

import com.teamwork.forexcalculator.user.models.Person;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

public class CustomOAuth2User implements OAuth2User {

    private final Person person;
    private final Map<String, Object> attributes;

    public CustomOAuth2User(Person person, Map<String, Object> attributes) {
        this.person = person;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(
                new SimpleGrantedAuthority("ROLE_" + person.getRole().name())
        );
    }

    @Override
    public String getName() {
        return person.getEmail();
    }

    public Person getPerson() {
        return person;
    }

}