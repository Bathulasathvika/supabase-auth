package com.example.supabase_auth.controller;

import com.example.supabase_auth.entity.AppUser;
import com.example.supabase_auth.entity.ForgotPasswordRequest;
import com.example.supabase_auth.repository.UserRepository;
import com.example.supabase_auth.service.FileUploadService;
import com.example.supabase_auth.service.JwtService;
import com.example.supabase_auth.service.SessionService;
import com.example.supabase_auth.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final UserRepository userRepository;
    private final FileUploadService fileUploadService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final SessionService sessionService;
    private final Map<String, String> otpStorage = new ConcurrentHashMap<>();

    @Autowired
    public AuthController(UserRepository userRepository,
                          FileUploadService fileUploadService,
                          PasswordEncoder passwordEncoder,
                          AuthenticationManager authenticationManager,
                          JwtService jwtService,
                          SessionService sessionService,
                          UserService userService) {
        this.userRepository = userRepository;
        this.fileUploadService = fileUploadService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.sessionService = sessionService;
        this.userService=userService;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody AppUser user) {
        try {
            if (userRepository.findByEmail(user.getEmail()).isPresent()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "status", "error",
                        "message", "Email already registered"
                ));
            }

            user.setPassword(passwordEncoder.encode(user.getPassword()));
            AppUser savedUser = userRepository.save(user);

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "Signup successful",
                    "user", Map.of(
                            "id", savedUser.getId(),
                            "email", savedUser.getEmail()
                    )
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Signup failed: " + e.getMessage()
            ));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> creds, HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            creds.get("email"),
                            creds.get("password")
                    )
            );

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            AppUser user = userRepository.findByEmail(userDetails.getUsername())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Generate JWT token
            String token = jwtService.generateToken(userDetails);

            // Create and save session
            sessionService.createSession(user, token);

            // Add token to response headers
            response.addHeader("Authorization", "Bearer " + token);
            response.addHeader("accessToken", token);

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "Login successful",
                    "user", Map.of(
                            "id", user.getId(),
                            "email", user.getEmail(),
                            "name", user.getName()
                    ),
                    "token", token
            ));
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "status", "error",
                    "message", "Invalid credentials"
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Login failed: " + e.getMessage()
            ));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        try {
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                sessionService.invalidateSession(token);
                return ResponseEntity.ok(Map.of(
                        "status", "success",
                        "message", "Logged out successfully"
                ));
            }
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "error",
                    "message", "Invalid token"
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Logout failed: " + e.getMessage()
            ));
        }
    }

    @PostMapping("/send-otp")
    public ResponseEntity<?> sendOtp(@RequestParam String email) {
        try {
            String otp = String.format("%06d", new Random().nextInt(999999));
            otpStorage.put(email, otp);

            // In production, send OTP via email/SMS
            System.out.println("[SECURITY] OTP for " + email + ": " + otp);

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

            Optional<AppUser> user = userRepository.findByEmail(email);
            if (user.isPresent()) {
                // Convert AppUser to UserDetails
                UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                        .username(user.get().getEmail())
                        .password(user.get().getPassword())
                        .authorities(Collections.emptyList())
                        .build();

                String token = jwtService.generateToken(userDetails);
                sessionService.createSession(user.get(), token);

                return ResponseEntity.ok(Map.of(
                        "status", "success",
                        "message", "OTP verified",
                        "token", token
                ));
            } else {
                AppUser newUser = new AppUser();
                newUser.setEmail(email);

                newUser.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
                AppUser savedUser = userRepository.save(newUser);


                UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                        .username(savedUser.getEmail())
                        .password(savedUser.getPassword())
                        .authorities(Collections.emptyList())
                        .build();

                String token = jwtService.generateToken(userDetails);
                sessionService.createSession(savedUser, token);

                return ResponseEntity.ok(Map.of(
                        "status", "success",
                        "message", "New user registered and verified",
                        "token", token
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
    public ResponseEntity<?> loginSuccess(HttpServletResponse response) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            OAuth2User oauthUser = (OAuth2User) auth.getPrincipal();

            String email = oauthUser.getAttribute("email");
            Optional<AppUser> user = userRepository.findByEmail(email);

            if (user.isEmpty()) {
                AppUser newUser = new AppUser();
                newUser.setEmail(email);
                newUser.setName(oauthUser.getAttribute("name"));
                user = Optional.of(userRepository.save(newUser));
            }


            UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                    .username(user.get().getEmail())
                    .password("")
                    .authorities(Collections.emptyList())
                    .build();


            String token = jwtService.generateToken(userDetails);
            sessionService.createSession(user.get(), token);


            response.addHeader("Authorization", "Bearer " + token);
            response.addHeader("accessToken", token);

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "OAuth login successful",
                    "user", user.get(),
                    "token", token
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Login failed: " + e.getMessage()
            ));
        }
    }

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) {
        try {
            String fileUrl = fileUploadService.uploadFile(file);
            return ResponseEntity.ok(fileUrl);
        } catch (IOException e) {
            return ResponseEntity.status(500).body("File upload failed");
        }
    }
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        userService.initiatePasswordReset(request.getEmail());
        return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "Password reset link sent to email"
        ));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(
            @RequestParam String token,
            @RequestParam String newPassword) {
        try {
            userService.resetPassword(token, newPassword);
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "Password reset successfully"
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "error",
                    "message", e.getMessage()
            ));
        }
    }
    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam String currentPassword,
            @RequestParam String newPassword) {
        try {
            String email = SecurityContextHolder.getContext().getAuthentication().getName();
            AppUser user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Verify current password
            if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
                throw new RuntimeException("Current password is incorrect");
            }

            // Update password
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);

            // Invalidate all sessions
            sessionService.invalidateAllSessionsForUser(user);

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "Password changed successfully"
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "error",
                    "message", e.getMessage()
            ));
        }
    }
    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam String email) {
        // Implement email verification logic
        return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "Verification email sent"
        ));
    }

    @GetMapping("/providers")
    public ResponseEntity<?> getAuthProviders() {
        return ResponseEntity.ok(Map.of(
                "status", "success",
                "providers", List.of("google", "github") // List your configured providers
        ));
    }
}



