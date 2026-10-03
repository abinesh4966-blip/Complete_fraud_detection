package com.FraudDetection.fraud_detection_system.controller;

import com.FraudDetection.fraud_detection_system.model.User;
import com.FraudDetection.fraud_detection_system.repository.UserRepository;
import com.FraudDetection.fraud_detection_system.service.AuditService;
import com.FraudDetection.fraud_detection_system.service.PasswordService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/profile")
@CrossOrigin(origins = "*")
public class ProfileController {

    private static final long MAX_IMAGE_BYTES = 200_000; // 200KB

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordService passwordService;

    @Autowired
    private AuditService auditService;

    private Optional<User> findUser(String login) {
        if (login == null || login.isBlank()) return Optional.empty();
        String q = login.trim();
        Optional<User> u = userRepository.findByUsername(q);
        if (u.isPresent()) return u;
        try {
            return userRepository.findByEmail(q);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private Map<String, Object> publicProfile(User u) {
        Map<String, Object> m = new HashMap<>();
        m.put("username", u.getUsername());
        m.put("email", u.getEmail());
        m.put("fullName", u.getFullName());
        m.put("role", u.getRole());
        m.put("accountNumber", u.getAccountNumber());
        m.put("phone", u.getPhone());
        m.put("profileImage", u.getProfileImage());
        m.put("mustChangePassword", u.isMustChangePassword());
        m.put("emailVerified", u.isEmailVerified());
        m.put("lastLoginAt", u.getLastLoginAt() != null ? u.getLastLoginAt().toString() : null);
        m.put("createdAt", u.getCreatedAt() != null ? u.getCreatedAt().toString() : null);
        m.put("profileUpdatedAt", u.getProfileUpdatedAt() != null ? u.getProfileUpdatedAt().toString() : null);
        return m;
    }

    @GetMapping
    public Map<String, Object> getProfile(@RequestParam String username) {
        Map<String, Object> res = new HashMap<>();
        Optional<User> opt = findUser(username);
        if (opt.isEmpty()) {
            res.put("success", false);
            res.put("message", "User not found");
            return res;
        }
        res.put("success", true);
        res.put("profile", publicProfile(opt.get()));
        return res;
    }

    @PutMapping("/update")
    public Map<String, Object> updateProfile(@RequestBody Map<String, String> body) {
        Map<String, Object> res = new HashMap<>();
        String username = body.getOrDefault("username", "").trim();
        Optional<User> opt = findUser(username);
        if (opt.isEmpty()) {
            res.put("success", false);
            res.put("message", "User not found");
            return res;
        }
        User u = opt.get();

        String fullName = body.get("fullName");
        String phone = body.get("phone");
        String email = body.get("email");

        if (fullName != null) {
            fullName = fullName.trim();
            if (fullName.length() > 80) {
                res.put("success", false);
                res.put("message", "Full name is too long (max 80 characters)");
                return res;
            }
            u.setFullName(fullName);
        }

        if (phone != null) {
            phone = phone.trim();
            if (!phone.isEmpty() && !phone.matches("^[0-9+\\-\\s]{6,20}$")) {
                res.put("success", false);
                res.put("message", "Invalid phone format");
                return res;
            }
            u.setPhone(phone.isEmpty() ? null : phone);
        }

        if (email != null) {
            email = email.trim().toLowerCase();
            if (!email.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")) {
                res.put("success", false);
                res.put("message", "Invalid email address");
                return res;
            }
            Optional<User> other = userRepository.findByEmail(email);
            if (other.isPresent() && !other.get().getId().equals(u.getId())) {
                res.put("success", false);
                res.put("message", "Email already in use");
                return res;
            }
            u.setEmail(email);
        }

        u.setProfileUpdatedAt(LocalDateTime.now());
        userRepository.save(u);
        auditService.log(u.getUsername(), u.getRole(), "PROFILE_UPDATE", "Profile details updated");

        res.put("success", true);
        res.put("message", "Profile updated");
        res.put("profile", publicProfile(u));
        return res;
    }

    @PostMapping("/change-password")
    public Map<String, Object> changePassword(@RequestBody Map<String, String> body) {
        Map<String, Object> res = new HashMap<>();
        String username = body.getOrDefault("username", "").trim();
        String currentPassword = body.getOrDefault("currentPassword", "");
        String newPassword = body.getOrDefault("newPassword", "");
        String confirmPassword = body.getOrDefault("confirmPassword", "");

        Optional<User> opt = findUser(username);
        if (opt.isEmpty()) {
            res.put("success", false);
            res.put("message", "User not found");
            return res;
        }
        User u = opt.get();

        if (!u.isMustChangePassword() && !passwordService.matches(currentPassword, u.getPassword())) {
            res.put("success", false);
            res.put("message", "Current password is incorrect");
            auditService.log(u.getUsername(), u.getRole(), "PASSWORD_CHANGE_FAIL", "Wrong current password");
            return res;
        }

        if (newPassword == null || newPassword.length() < 8) {
            res.put("success", false);
            res.put("message", "New password must be at least 8 characters");
            return res;
        }
        if (!newPassword.equals(confirmPassword)) {
            res.put("success", false);
            res.put("message", "New password and confirmation do not match");
            return res;
        }
        if (!newPassword.matches(".*[A-Z].*") || !newPassword.matches(".*[a-z].*") || !newPassword.matches(".*[0-9].*")) {
            res.put("success", false);
            res.put("message", "Password must include uppercase, lowercase, and a number");
            return res;
        }
        if (passwordService.matches(newPassword, u.getPassword())) {
            res.put("success", false);
            res.put("message", "New password must be different from the current password");
            return res;
        }

        u.setPassword(passwordService.hash(newPassword));
        u.setMustChangePassword(false);
        u.setProfileUpdatedAt(LocalDateTime.now());
        userRepository.save(u);
        auditService.log(u.getUsername(), u.getRole(), "PASSWORD_CHANGE", "Password changed successfully");

        res.put("success", true);
        res.put("message", "Password changed successfully");
        return res;
    }

    @PostMapping(value = "/avatar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Map<String, Object> uploadAvatar(@RequestParam String username,
                                            @RequestParam("file") MultipartFile file) {
        Map<String, Object> res = new HashMap<>();
        Optional<User> opt = findUser(username);
        if (opt.isEmpty()) {
            res.put("success", false);
            res.put("message", "User not found");
            return res;
        }
        if (file == null || file.isEmpty()) {
            res.put("success", false);
            res.put("message", "No file uploaded");
            return res;
        }
        if (file.getSize() > MAX_IMAGE_BYTES) {
            res.put("success", false);
            res.put("message", "Image too large (max 200KB)");
            return res;
        }
        String contentType = file.getContentType() != null ? file.getContentType().toLowerCase() : "";
        if (!contentType.equals("image/jpeg") && !contentType.equals("image/png") && !contentType.equals("image/jpg")) {
            res.put("success", false);
            res.put("message", "Only JPEG or PNG images are allowed");
            return res;
        }

        try {
            String b64 = Base64.getEncoder().encodeToString(file.getBytes());
            String dataUrl = "data:" + contentType + ";base64," + b64;
            if (dataUrl.length() > 340000) {
                res.put("success", false);
                res.put("message", "Encoded image exceeds storage limit — use a smaller file");
                return res;
            }
            User u = opt.get();
            u.setProfileImage(dataUrl);
            u.setProfileUpdatedAt(LocalDateTime.now());
            userRepository.save(u);
            auditService.log(u.getUsername(), u.getRole(), "AVATAR_UPDATE", "Profile image updated");
            res.put("success", true);
            res.put("message", "Profile picture updated");
            res.put("profileImage", dataUrl);
        } catch (Exception e) {
            res.put("success", false);
            res.put("message", "Upload failed: " + e.getMessage());
        }
        return res;
    }

    @DeleteMapping("/avatar")
    public Map<String, Object> removeAvatar(@RequestParam String username) {
        Map<String, Object> res = new HashMap<>();
        Optional<User> opt = findUser(username);
        if (opt.isEmpty()) {
            res.put("success", false);
            res.put("message", "User not found");
            return res;
        }
        User u = opt.get();
        u.setProfileImage(null);
        u.setProfileUpdatedAt(LocalDateTime.now());
        userRepository.save(u);
        auditService.log(u.getUsername(), u.getRole(), "AVATAR_REMOVE", "Profile image removed");
        res.put("success", true);
        res.put("message", "Profile picture removed");
        return res;
    }
}
