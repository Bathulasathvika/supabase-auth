package com.example.supabase_auth.service;

import com.example.supabase_auth.entity.AppUser;
import com.example.supabase_auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        String provider = userRequest.getClientRegistration().getRegistrationId(); // e.g., "google", "github"

        Optional<AppUser> user = userRepository.findByEmail(email);
        if (user.isEmpty()) {
            AppUser newUser = new AppUser();
            newUser.setEmail(email);
            newUser.setName(name);
            newUser.setProvider(provider);
            newUser.setEnabled(true);
            newUser.setCreatedAt(LocalDateTime.now());
            userRepository.save(newUser);
        } else {
            // Update existing user with provider info if needed
            AppUser existingUser = user.get();
            if (existingUser.getProvider() == null || !existingUser.getProvider().equals(provider)) {
                existingUser.setProvider(provider);
                userRepository.save(existingUser);
            }
        }

        return oAuth2User;
    }
}