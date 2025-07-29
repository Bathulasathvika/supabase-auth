package com.example.supabase_auth.repository;

import com.example.supabase_auth.entity.AppUser;
import com.example.supabase_auth.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    List<UserSession> findByUser(AppUser user);
    List<UserSession> findByUserAndActiveTrue(AppUser user);
    Optional<UserSession> findByToken(String token);
}