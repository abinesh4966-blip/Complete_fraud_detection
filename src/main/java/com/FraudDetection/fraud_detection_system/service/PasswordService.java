package com.FraudDetection.fraud_detection_system.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * BCrypt primary hashing with legacy SHA-256 verification + transparent upgrade.
 */
@Service
public class PasswordService {

    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(10);

    public String hash(String raw) {
        return bcrypt.encode(raw);
    }

    public boolean matches(String raw, String stored) {
        if (raw == null || stored == null) return false;
        if (stored.startsWith("$2a$") || stored.startsWith("$2b$") || stored.startsWith("$2y$")) {
            return bcrypt.matches(raw, stored);
        }
        // Legacy SHA-256 hex (old FYP builds)
        return sha256(raw).equalsIgnoreCase(stored);
    }

    /** True if stored hash should be upgraded to BCrypt after successful login */
    public boolean needsUpgrade(String stored) {
        return stored != null && !(stored.startsWith("$2a$") || stored.startsWith("$2b$") || stored.startsWith("$2y$"));
    }

    private String sha256(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
