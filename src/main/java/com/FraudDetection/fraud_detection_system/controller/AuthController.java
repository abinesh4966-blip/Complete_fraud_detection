package com.FraudDetection.fraud_detection_system.controller;

import com.FraudDetection.fraud_detection_system.model.User;
import com.FraudDetection.fraud_detection_system.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    private final SecureRandom random = new SecureRandom();

    /** captchaId -> code */
    private final Map<String, String> captchas = new ConcurrentHashMap<>();
    /** key -> otp */
    private final Map<String, OtpEntry> otps = new ConcurrentHashMap<>();

    private static class OtpEntry {
        String code;
        LocalDateTime expires;
        String purpose; // LOGIN_2FA | RESET
        String login;   // username/email
        OtpEntry(String code, LocalDateTime expires, String purpose, String login) {
            this.code = code;
            this.expires = expires;
            this.purpose = purpose;
            this.login = login;
        }
    }

    @PostConstruct
    public void ensureSuperAdmin() {
        boolean hasSuper = userRepository.findAll().stream()
                .anyMatch(u -> "SUPER_ADMIN".equalsIgnoreCase(u.getRole()));
        if (!hasSuper) {
            User su = new User();
            su.setUsername("superadmin");
            su.setEmail("superadmin@bsn-fds.local");
            su.setPassword(hashPassword("SuperAdmin@123"));
            su.setFullName("System Super Admin");
            su.setRole("SUPER_ADMIN");
            su.setAccountNumber("SUPER-001");
            su.setCreatedAt(LocalDateTime.now());
            su.setEmailVerified(true);
            userRepository.save(su);
            System.out.println("=== SUPER ADMIN CREATED ===");
            System.out.println("username: superadmin");
            System.out.println("password: SuperAdmin@123");
            System.out.println("CHANGE THIS AFTER FIRST LOGIN");
        }
    }

    private String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                String h = Integer.toHexString(0xff & b);
                if (h.length() == 1) hex.append('0');
                hex.append(h);
            }
            return hex.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private boolean validPassword(String p) {
        if (p == null || p.length() < 8) return false;
        return p.matches(".*[A-Z].*") && p.matches(".*[0-9].*") && p.matches(".*[^A-Za-z0-9].*");
    }

    private boolean validUsername(String u) {
        return u != null && u.matches("^[A-Za-z0-9._@-]{4,40}$");
    }

    private boolean validEmail(String e) {
        return e != null && e.matches("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    }

    // ---------- CAPTCHA ----------
    @GetMapping("/captcha")
    public Map<String, String> captcha() {
        String id = Long.toString(Math.abs(random.nextLong()), 36);
        String chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        StringBuilder code = new StringBuilder();
        for (int i = 0; i < 5; i++) code.append(chars.charAt(random.nextInt(chars.length())));
        captchas.put(id, code.toString());
        return Map.of("captchaId", id, "captchaCode", code.toString()); // code for canvas draw; also returned for accessibility in demo
    }

    private String checkCaptcha(String id, String input) {
        if (id == null || input == null || input.isBlank()) return "CAPTCHA is required";
        String expected = captchas.get(id);
        if (expected == null) return "CAPTCHA expired. Please try a new one";
        captchas.remove(id);
        if (!expected.equalsIgnoreCase(input.trim())) return "CAPTCHA is incorrect";
        return null;
    }

    private Optional<User> findLogin(String login) {
        if (login == null || login.isBlank()) return Optional.empty();
        String q = login.trim();
        Optional<User> byUser = userRepository.findByUsername(q);
        if (byUser.isPresent()) return byUser;
        return userRepository.findByEmail(q);
    }

    private Map<String, Object> lockInfo(User u) {
        if (u.getLockoutUntil() != null && u.getLockoutUntil().isAfter(LocalDateTime.now())) {
            return Map.of(
                    "success", false,
                    "message", "Account locked until " + u.getLockoutUntil() + ". Please try later.",
                    "locked", true,
                    "lockoutUntil", u.getLockoutUntil().toString()
            );
        }
        return null;
    }

    private void registerFailure(User u) {
        int fails = u.getFailedAttempts() + 1;
        u.setFailedAttempts(fails);
        if (fails >= 3) {
            int level = Math.min(u.getLockoutLevel() + 1, 3);
            u.setLockoutLevel(level);
            u.setFailedAttempts(0);
            int hours = level == 1 ? 1 : (level == 2 ? 6 : 24);
            u.setLockoutUntil(LocalDateTime.now().plusHours(hours));
        }
        userRepository.save(u);
    }

    private void clearFailures(User u) {
        u.setFailedAttempts(0);
        u.setLockoutUntil(null);
        // keep lockoutLevel history, or reset on success:
        u.setLockoutLevel(0);
        userRepository.save(u);
    }

    // ---------- REGISTER (USER only) ----------
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
        String fullName = body.getOrDefault("fullName", "").trim();
        String username = body.getOrDefault("username", "").trim();
        String email = body.getOrDefault("email", "").trim().toLowerCase();
        String password = body.getOrDefault("password", "");
        String captchaId = body.get("captchaId");
        String captchaInput = body.get("captchaInput");

        if (fullName.isEmpty())
            return ResponseEntity.badRequest().body(Map.of("success", false, "field", "fullName", "message", "Full name is required"));
        if (!validUsername(username))
            return ResponseEntity.badRequest().body(Map.of("success", false, "field", "username", "message", "Username must be 4–40 chars (letters, numbers, . _ @ -)"));
        if (userRepository.existsByUsername(username))
            return ResponseEntity.badRequest().body(Map.of("success", false, "field", "username", "message", "Username is already taken"));
        if (!validEmail(email))
            return ResponseEntity.badRequest().body(Map.of("success", false, "field", "email", "message", "Valid email is required"));
        if (userRepository.existsByEmail(email))
            return ResponseEntity.badRequest().body(Map.of("success", false, "field", "email", "message", "Email is already registered"));
        if (!validPassword(password))
            return ResponseEntity.badRequest().body(Map.of("success", false, "field", "password", "message", "Password must be min 8 chars, 1 uppercase, 1 number, 1 special character"));

        String capErr = checkCaptcha(captchaId, captchaInput);
        if (capErr != null)
            return ResponseEntity.badRequest().body(Map.of("success", false, "field", "captcha", "message", capErr));

        User u = new User();
        u.setFullName(fullName);
        u.setUsername(username);
        u.setEmail(email);
        u.setPassword(hashPassword(password));
        u.setRole("USER");
        u.setAccountNumber("ACC" + System.currentTimeMillis() % 1000000);
        u.setCreatedAt(LocalDateTime.now());
        userRepository.save(u);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Registration successful",
                "username", u.getUsername(),
                "email", u.getEmail(),
                "role", u.getRole(),
                "accountNumber", u.getAccountNumber(),
                "autoLogin", true
        ));
    }

    // ---------- LOGIN (username OR email) ----------
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String login = body.getOrDefault("login", body.getOrDefault("username", "")).trim();
        String password = body.getOrDefault("password", "");
        String captchaId = body.get("captchaId");
        String captchaInput = body.get("captchaInput");
        String otp = body.get("otp"); // optional 2FA step

        if (login.isEmpty())
            return ResponseEntity.badRequest().body(Map.of("success", false, "field", "login", "message", "Username or email is required"));
        if (password.isEmpty())
            return ResponseEntity.badRequest().body(Map.of("success", false, "field", "password", "message", "Password is required"));

        String capErr = checkCaptcha(captchaId, captchaInput);
        if (capErr != null)
            return ResponseEntity.badRequest().body(Map.of("success", false, "field", "captcha", "message", capErr));

        Optional<User> opt = findLogin(login);
        if (opt.isEmpty())
            return ResponseEntity.status(401).body(Map.of("success", false, "message", "Invalid username/email or password"));

        User u = opt.get();
        Map<String, Object> locked = lockInfo(u);
        if (locked != null) return ResponseEntity.status(423).body(locked);

        if (!u.getPassword().equals(hashPassword(password))) {
            registerFailure(u);
            String msg = "Invalid username/email or password";
            if (u.getLockoutUntil() != null && u.getLockoutUntil().isAfter(LocalDateTime.now())) {
                msg = "Too many failed attempts. Account locked until " + u.getLockoutUntil();
            } else {
                msg += ". Attempts left before lockout: " + Math.max(0, 3 - u.getFailedAttempts());
            }
            return ResponseEntity.status(401).body(Map.of("success", false, "message", msg));
        }

        // Optional 2FA: if client asks require2fa=true, issue OTP instead of full login
        boolean require2fa = "true".equalsIgnoreCase(body.getOrDefault("require2fa", "false"));
        if (require2fa && (otp == null || otp.isBlank())) {
            String code = String.format("%06d", random.nextInt(1_000_000));
            String key = "2FA:" + u.getUsername();
            otps.put(key, new OtpEntry(code, LocalDateTime.now().plusMinutes(10), "LOGIN_2FA", u.getUsername()));
            // Demo: return OTP when real email SMTP is not configured
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "require2fa", true,
                    "message", "OTP sent to registered email (demo may show code)",
                    "demoOtp", code,
                    "emailHint", maskEmail(u.getEmail())
            ));
        }
        if (require2fa) {
            OtpEntry entry = otps.get("2FA:" + u.getUsername());
            if (entry == null || entry.expires.isBefore(LocalDateTime.now()) || !entry.code.equals(otp.trim())) {
                return ResponseEntity.status(401).body(Map.of("success", false, "field", "otp", "message", "Invalid or expired OTP"));
            }
            otps.remove("2FA:" + u.getUsername());
        }

        clearFailures(u);
        u.setLastLoginAt(LocalDateTime.now());
        userRepository.save(u);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Login successful",
                "username", u.getUsername(),
                "email", u.getEmail() != null ? u.getEmail() : "",
                "fullName", u.getFullName() != null ? u.getFullName() : "",
                "role", u.getRole(),
                "accountNumber", u.getAccountNumber() != null ? u.getAccountNumber() : ""
        ));
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) return "***";
        int at = email.indexOf('@');
        String name = email.substring(0, at);
        String domain = email.substring(at);
        if (name.length() <= 2) return "***" + domain;
        return name.substring(0, 2) + "***" + domain;
    }

    // ---------- FORGOT PASSWORD ----------
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgot(@RequestBody Map<String, String> body) {
        String login = body.getOrDefault("login", "").trim();
        Optional<User> opt = findLogin(login);
        // Always generic message (don't reveal if user exists)
        if (opt.isEmpty()) {
            return ResponseEntity.ok(Map.of("success", true, "message", "If the account exists, a reset code was issued"));
        }
        User u = opt.get();
        String code = String.format("%06d", random.nextInt(1_000_000));
        otps.put("RESET:" + u.getUsername(), new OtpEntry(code, LocalDateTime.now().plusMinutes(15), "RESET", u.getUsername()));
        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "If the account exists, a reset code was issued",
                "demoOtp", code
        ));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> reset(@RequestBody Map<String, String> body) {
        String login = body.getOrDefault("login", "").trim();
        String otp = body.getOrDefault("otp", "").trim();
        String newPassword = body.getOrDefault("newPassword", "");

        Optional<User> opt = findLogin(login);
        if (opt.isEmpty())
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "Invalid reset request"));

        User u = opt.get();
        OtpEntry entry = otps.get("RESET:" + u.getUsername());
        if (entry == null || entry.expires.isBefore(LocalDateTime.now()) || !entry.code.equals(otp))
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "Invalid or expired reset code"));
        if (!validPassword(newPassword))
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "Password must be min 8 chars, 1 uppercase, 1 number, 1 special character"));

        u.setPassword(hashPassword(newPassword));
        clearFailures(u);
        otps.remove("RESET:" + u.getUsername());
        userRepository.save(u);
        return ResponseEntity.ok(Map.of("success", true, "message", "Password updated. You can log in now"));
    }
}