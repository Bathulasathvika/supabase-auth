package com.example.supabase_auth.service;

import com.example.supabase_auth.entity.AppUser;
import com.example.supabase_auth.entity.UserSession;
import com.example.supabase_auth.repository.UserSessionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class SessionService {
    @Autowired
    private UserSessionRepository userSessionRepository;

    @Autowired
    private JwtService jwtService;

    @Transactional
    public UserSession createSession(AppUser user, String token) {
        // Invalidate any existing active sessions
        List<UserSession> activeSessions = userSessionRepository.findByUserAndActiveTrue(user);
        activeSessions.forEach(session -> {
            session.setActive(false);
            userSessionRepository.save(session);
        });

        // Create new session
        UserSession session = new UserSession();
        session.setUser(user);
        session.setToken(token);
        session.setCreatedAt(LocalDateTime.now());
        session.setExpiresAt(LocalDateTime.now().plusSeconds(jwtService.getJwtExpiration() / 1000));
        session.setActive(true);

        return userSessionRepository.save(session);
    }

    @Transactional
    public void invalidateSession(String token) {
        userSessionRepository.findByToken(token).ifPresent(session -> {
            session.setActive(false);
            userSessionRepository.save(session);
        });
    }


    @Transactional
    public void invalidateAllSessionsForUser(AppUser user) {
        List<UserSession> sessions = userSessionRepository.findByUser(user);
        sessions.forEach(session -> {
            session.setActive(false);
            userSessionRepository.save(session);
        });
    }
}
