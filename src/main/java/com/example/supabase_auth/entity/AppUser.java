package com.example.supabase_auth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

import java.time.LocalDateTime;

@Entity
@Table(name="users")
public class AppUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)

    private Long id;
    private String username;
    private String password;
    private String email;
    private String resetToken;
    private LocalDateTime resetTokenExpiry;
    private String provider;



    @Column(nullable = false, columnDefinition = "boolean default true")
    private boolean enabled = true;

    private LocalDateTime createdAt;

    // Getters and setters
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }


    public void setName(String name) {
        this.username = name;
    }
    public String getResetToken() {
        return resetToken;
    }

    public void setResetToken(String resetToken) {
        this.resetToken = resetToken;
    }

    public LocalDateTime getResetTokenExpiry() {
        return resetTokenExpiry;
    }

    public void setResetTokenExpiry(LocalDateTime resetTokenExpiry) {
        this.resetTokenExpiry = resetTokenExpiry;
    }
    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }
}
