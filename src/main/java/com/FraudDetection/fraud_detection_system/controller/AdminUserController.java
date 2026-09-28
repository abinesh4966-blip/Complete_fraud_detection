package com.FraudDetection.fraud_detection_system.controller;

import com.FraudDetection.fraud_detection_system.model.Transaction;
import com.FraudDetection.fraud_detection_system.model.User;
import com.FraudDetection.fraud_detection_system.repository.TransactionRepository;
import com.FraudDetection.fraud_detection_system.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.*;

@RestController
@RequestMapping("/api/admin/users")
@CrossOrigin(origins = "*")
public class AdminUserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TransactionRepository transactionRepository;

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

    private User requireActor(String actorUsername) {
        if (actorUsername == null || actorUsername.isBlank()) return null;
        return userRepository.findByUsername(actorUsername.trim()).orElse(null);
    }

    private boolean isSuper(User u) {
        return u != null && "SUPER_ADMIN".equalsIgnoreCase(u.getRole());
    }

    private boolean isAdminStaff(User u) {
        if (u == null || u.getRole() == null) return false;
        String r = u.getRole().toUpperCase();
        return r.equals("ADMIN") || r.equals("SUPER_ADMIN");
    }

    @GetMapping("/summary")
    public Map<String, Object> summary() {
        Map<String, Object> res = new HashMap<>();
        try {
            List<User> users = userRepository.findAll();
            List<Transaction> txs = transactionRepository.findAll();
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime dayAgo = now.minusHours(24);
            LocalDateTime weekAgo = now.minusDays(7);

            long userRole = 0, adminRole = 0, superRole = 0, locked = 0, active24h = 0, active7d = 0;
            for (User u : users) {
                if (u == null) continue;
                String role = u.getRole() != null ? u.getRole().toUpperCase() : "USER";
                if ("SUPER_ADMIN".equals(role)) superRole++;
                else if ("ADMIN".equals(role)) adminRole++;
                else userRole++;
                if (u.getLockoutUntil() != null && u.getLockoutUntil().isAfter(now)) locked++;
                if (u.getLastLoginAt() != null && u.getLastLoginAt().isAfter(dayAgo)) active24h++;
                if (u.getLastLoginAt() != null && u.getLastLoginAt().isAfter(weekAgo)) active7d++;
            }

            long flaggedTx = 0;
            for (Transaction t : txs) {
                if (t == null) continue;
                if ("SUSPICIOUS".equals(t.getStatus()) && !t.isFalsePositive()) flaggedTx++;
            }

            res.put("success", true);
            res.put("totalUsers", users.size());
            res.put("userAccounts", userRole);
            res.put("adminAccounts", adminRole);
            res.put("superAdminAccounts", superRole);
            res.put("lockedAccounts", locked);
            res.put("activeLast24h", active24h);
            res.put("activeLast7d", active7d);
            res.put("totalTransactions", txs.size());
            res.put("flaggedTransactions", flaggedTx);
        } catch (Exception e) {
            res.put("success", false);
            res.put("message", e.getMessage());
        }
        return res;
    }

    @GetMapping("/list")
    public List<Map<String, Object>> list() {
        List<Map<String, Object>> rows = new ArrayList<>();
        try {
            List<User> users = userRepository.findAll();
            List<Transaction> txs = transactionRepository.findAll();
            LocalDateTime now = LocalDateTime.now();

            for (User u : users) {
                if (u == null) continue;
                long txCount = 0, txFlagged = 0;
                String acc = u.getAccountNumber();
                for (Transaction t : txs) {
                    if (t == null) continue;
                    if (acc != null && acc.equals(t.getAccountNumber())) {
                        txCount++;
                        if ("SUSPICIOUS".equals(t.getStatus()) && !t.isFalsePositive()) txFlagged++;
                    }
                }
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("id", u.getId());
                row.put("username", u.getUsername());
                row.put("email", u.getEmail());
                row.put("fullName", u.getFullName());
                row.put("role", u.getRole());
                row.put("accountNumber", u.getAccountNumber());
                row.put("failedAttempts", u.getFailedAttempts());
                row.put("lockoutLevel", u.getLockoutLevel());
                row.put("locked", u.getLockoutUntil() != null && u.getLockoutUntil().isAfter(now));
                row.put("lockoutUntil", u.getLockoutUntil() != null ? u.getLockoutUntil().toString() : null);
                row.put("lastLoginAt", u.getLastLoginAt() != null ? u.getLastLoginAt().toString() : null);
                row.put("createdAt", u.getCreatedAt() != null ? u.getCreatedAt().toString() : null);
                row.put("txCount", txCount);
                row.put("txFlagged", txFlagged);
                rows.add(row);
            }
            rows.sort((a, b) -> Long.compare(
                    ((Number) b.get("txFlagged")).longValue(),
                    ((Number) a.get("txFlagged")).longValue()
            ));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return rows;
    }

    @PutMapping("/{id}/unlock")
    public Map<String, Object> unlock(@PathVariable Long id) {
        Map<String, Object> res = new HashMap<>();
        try {
            Optional<User> opt = userRepository.findById(id);
            if (opt.isEmpty()) {
                res.put("success", false);
                res.put("message", "User not found");
                return res;
            }
            User u = opt.get();
            u.setFailedAttempts(0);
            u.setLockoutUntil(null);
            userRepository.save(u);
            res.put("success", true);
            res.put("message", "Account unlocked: " + u.getUsername());
        } catch (Exception e) {
            res.put("success", false);
            res.put("message", e.getMessage());
        }
        return res;
    }

    /** SuperAdmin only — create ADMIN account */
    @PostMapping("/admins")
    public Map<String, Object> createAdmin(@RequestBody Map<String, String> body) {
        Map<String, Object> res = new HashMap<>();
        try {
            String actorUsername = body.getOrDefault("actorUsername", "").trim();
            User actor = requireActor(actorUsername);
            if (!isSuper(actor)) {
                res.put("success", false);
                res.put("message", "Only SuperAdmin can add admin accounts");
                return res;
            }

            String username = body.getOrDefault("username", "").trim();
            String email = body.getOrDefault("email", "").trim().toLowerCase();
            String password = body.getOrDefault("password", "");
            String fullName = body.getOrDefault("fullName", "").trim();

            if (username.length() < 4) {
                res.put("success", false);
                res.put("message", "Username must be at least 4 characters");
                return res;
            }
            if (userRepository.existsByUsername(username)) {
                res.put("success", false);
                res.put("message", "Username already taken");
                return res;
            }
            if (email.isEmpty() || !email.contains("@")) {
                res.put("success", false);
                res.put("message", "Valid email required");
                return res;
            }
            if (userRepository.existsByEmail(email)) {
                res.put("success", false);
                res.put("message", "Email already registered");
                return res;
            }
            if (password.length() < 8) {
                res.put("success", false);
                res.put("message", "Password must be at least 8 characters");
                return res;
            }

            User admin = new User();
            admin.setUsername(username);
            admin.setEmail(email);
            admin.setFullName(fullName.isEmpty() ? username : fullName);
            admin.setPassword(hashPassword(password));
            admin.setRole("ADMIN");
            admin.setAccountNumber("ADM" + (System.currentTimeMillis() % 1_000_000));
            admin.setCreatedAt(LocalDateTime.now());
            admin.setEmailVerified(true);
            userRepository.save(admin);

            res.put("success", true);
            res.put("message", "Admin created: " + username);
            res.put("id", admin.getId());
        } catch (Exception e) {
            res.put("success", false);
            res.put("message", e.getMessage());
        }
        return res;
    }

    /** SuperAdmin only — remove ADMIN (not SUPER_ADMIN, not USER) */
    @DeleteMapping("/admins/{id}")
    public Map<String, Object> removeAdmin(@PathVariable Long id,
                                           @RequestParam String actorUsername) {
        Map<String, Object> res = new HashMap<>();
        try {
            User actor = requireActor(actorUsername);
            if (!isSuper(actor)) {
                res.put("success", false);
                res.put("message", "Only SuperAdmin can remove admin accounts");
                return res;
            }
            Optional<User> opt = userRepository.findById(id);
            if (opt.isEmpty()) {
                res.put("success", false);
                res.put("message", "User not found");
                return res;
            }
            User target = opt.get();
            if ("SUPER_ADMIN".equalsIgnoreCase(target.getRole())) {
                res.put("success", false);
                res.put("message", "Cannot remove SuperAdmin");
                return res;
            }
            if (!"ADMIN".equalsIgnoreCase(target.getRole())) {
                res.put("success", false);
                res.put("message", "Target is not an admin account");
                return res;
            }
            if (actor.getId() != null && actor.getId().equals(target.getId())) {
                res.put("success", false);
                res.put("message", "Cannot remove yourself");
                return res;
            }
            String name = target.getUsername();
            userRepository.delete(target);
            res.put("success", true);
            res.put("message", "Admin removed: " + name);
        } catch (Exception e) {
            res.put("success", false);
            res.put("message", e.getMessage());
        }
        return res;
    }
}