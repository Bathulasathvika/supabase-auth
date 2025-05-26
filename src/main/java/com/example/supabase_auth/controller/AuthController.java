package com.example.supabase_auth.controller;

import com.example.supabase_auth.AppUser;
import com.example.supabase_auth.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    private final Map<String, String> otpStorage = new ConcurrentHashMap<>();
    private final Map<String, String> emailToOtpMap = new ConcurrentHashMap<>();


    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody AppUser user) {
        try {
            if (userRepository.findByEmail(user.getEmail()).isPresent()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "status", "error",
                        "message", "Email already registered"
                ));
            }

            user.setVerified(false);
            userRepository.save(user);
            

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "Signup successful. Please verify via OTP."
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Signup failed: " + e.getMessage()
            ));
        }
    }


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> creds) {
        try {
            Optional<AppUser> user = userRepository.findByEmail(creds.get("email"));

            if (user.isEmpty() || !user.get().getPassword().equals(creds.get("password"))) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                        "status", "error",
                        "message", "Invalid credentials"
                ));
            }

            if (!user.get().isVerified()) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                        "status", "error",
                        "message", "Account not verified. Please verify via OTP."
                ));
            }

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "Login successful",
                    "user", user.get()
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Login failed: " + e.getMessage()
            ));
        }
    }


    @PostMapping("/send-otp")
    public ResponseEntity<?> sendOtp(@RequestParam String email) {
        try {
            String otp = String.format("%06d", new Random().nextInt(999999));
            otpStorage.put(email, otp);
            emailToOtpMap.put(email, otp);

            System.out.println("OTP for " + email + ": " + otp); // Simulate sending

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "OTP sent to email",
                    "email", email
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Failed to send OTP: " + e.getMessage()
            ));
        }
    }


    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestParam String email, @RequestParam String otp) {
        try {
            String storedOtp = otpStorage.get(email);

            if (storedOtp == null || !storedOtp.equals(otp)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                        "status", "error",
                        "message", "Invalid OTP"
                ));
            }

            otpStorage.remove(email);
            emailToOtpMap.remove(email);

            Optional<AppUser> user = userRepository.findByEmail(email);
            if (user.isPresent()) {
                user.get().setVerified(true);
                userRepository.save(user.get());

                return ResponseEntity.ok(Map.of(
                        "status", "success",
                        "message", "OTP verified. Account activated.",
                        "user", user.get()
                ));
            } else {
                AppUser newUser = new AppUser();
                newUser.setEmail(email);
                newUser.setVerified(true);
                userRepository.save(newUser);

                return ResponseEntity.ok(Map.of(
                        "status", "success",
                        "message", "New user registered and verified",
                        "user", newUser
                ));
            }
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "OTP verification failed: " + e.getMessage()
            ));
        }
    }


    @GetMapping("/oauth-success")
    public ResponseEntity<?> loginSuccess() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !auth.isAuthenticated()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                        "status", "error",
                        "message", "Not authenticated"
                ));
            }

            OAuth2User oauthUser = (OAuth2User) auth.getPrincipal();
            String email = oauthUser.getAttribute("email");

            if (email == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                        "status", "error",
                        "message", "Email not provided by OAuth provider"
                ));
            }

            Optional<AppUser> user = userRepository.findByEmail(email);
            if (user.isEmpty()) {
                AppUser newUser = new AppUser();
                newUser.setEmail(email);
                newUser.setName(oauthUser.getAttribute("name"));
                newUser.setVerified(true);
                userRepository.save(newUser);
                user = Optional.of(newUser);
            }

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "OAuth login successful",
                    "user", user.get()
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Login failed: " + e.getMessage()
            ));
        }
    }


    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                        "status", "error",
                        "message", "Not authenticated"
                ));
            }

            String email = null;

            if (authentication.getPrincipal() instanceof OAuth2User oauthUser) {
                email = oauthUser.getAttribute("email");
            } else if (authentication.getPrincipal() instanceof String s) {
                email = s;
            }

            if (email == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                        "status", "error",
                        "message", "Unable to determine user identity"
                ));
            }

            Optional<AppUser> user = userRepository.findByEmail(email);

            if (user.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of(
                        "status", "error",
                        "message", "User not found"
                ));
            }

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "user", user.get()
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Failed to fetch user: " + e.getMessage()
            ));
        }
    }


    @GetMapping("/oauth2-url")
    public ResponseEntity<?> getOAuth2Url() {
        return ResponseEntity.ok(Map.of(
                "google", "/oauth2/authorization/google",
                "_self", "/auth/me"
        ));
    }


    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) throws ServletException {
        request.logout();
        return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "Logged out successfully"
        ));
    }
}
