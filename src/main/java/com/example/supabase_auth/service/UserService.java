package com.example.supabase_auth.service;

import com.example.supabase_auth.entity.AppUser;
import com.example.supabase_auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        List<SimpleGrantedAuthority> authorities = Collections.singletonList(
                new SimpleGrantedAuthority("ROLE_USER")
        );

        return new User(
                user.getEmail(),
                user.getPassword(),
                user.isEnabled(),
                true,
                true,
                true,
                authorities
        );
    }

    public AppUser registerUser(AppUser user) {
        String hashedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(hashedPassword);
        user.setEnabled(true);
        user.setCreatedAt(LocalDateTime.now());
        return userRepository.save(user);
    }

    public void initiatePasswordReset(String email) {
        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        String resetToken = UUID.randomUUID().toString();
        user.setResetToken(resetToken);
        user.setResetTokenExpiry(LocalDateTime.now().plusHours(24)); // Token valid for 24 hours
        userRepository.save(user);


        System.out.println("[SECURITY] Password reset token for " + email + ": " + resetToken);
    }

    public void resetPassword(String token, String newPassword) {
        AppUser user = userRepository.findByResetToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid reset token"));

        if (user.getResetTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Reset token has expired");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetToken(null);
        user.setResetTokenExpiry(null);
        userRepository.save(user);
    }
}