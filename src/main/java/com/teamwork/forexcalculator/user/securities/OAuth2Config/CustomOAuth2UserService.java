package com.teamwork.forexcalculator.user.securities.OAuth2Config;

import com.teamwork.forexcalculator.user.models.Person;
import com.teamwork.forexcalculator.user.models.Role;
import com.teamwork.forexcalculator.user.repository.PersonRepo;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final PersonRepo personRepo;

    public CustomOAuth2UserService(PersonRepo personRepo) {
        this.personRepo = personRepo;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // Extract user information
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        // Check if user exists in your database
        Person person = personRepo.findByEmail(email)
                .orElseGet(() -> {
                    // Create new user if not exists
                    Person newUser = new Person();
                    newUser.setEmail(email);
                    newUser.setFirstName(name);
                    newUser.setVerified(true);
                    newUser.setRole(Role.USER);
                    return personRepo.save(newUser);
                });

        return new CustomOAuth2User(person, oAuth2User.getAttributes());
    }
}