package com.example.supabase_auth.controller;

import com.example.supabase_auth.entity.AppUser;
import com.example.supabase_auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return ResponseEntity.ok(Map.of(
                "status", "success",
                "user", Map.of(
                        "id", user.getId(),
                        "email", user.getEmail(),
                        "name", user.getName(),
                        "createdAt", user.getCreatedAt()
                )

        ));
    }

    @PutMapping("/profile")
    public ResponseEntity<?> updateProfile(@RequestBody Map<String, String> updates) {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (updates.containsKey("name")) {
            user.setName(updates.get("name"));
        }

        userRepository.save(user);

        return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "Profile updated successfully"
        ));
    }
}
