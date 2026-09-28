package com.FraudDetection.fraud_detection_system.controller;

import com.FraudDetection.fraud_detection_system.model.Transaction;
import com.FraudDetection.fraud_detection_system.model.User;
import com.FraudDetection.fraud_detection_system.repository.TransactionRepository;
import com.FraudDetection.fraud_detection_system.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
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
            throw new RuntimeException("Error hashing password", e);
        }
    }

    private Optional<User> requireSuperAdmin(String actorUsername) {
        if (actorUsername == null || actorUsername.isBlank()) return Optional.empty();
        Optional<User> opt = userRepository.findByUsername(actorUsername.trim());
        if (opt.isEmpty()) return Optional.empty();
        if (!"SUPER_ADMIN".equalsIgnoreCase(opt.get().getRole())) return Optional.empty();
        return opt;
    }

    private Optional<User> requireAdminOrSuper(String actorUsername) {
        if (actorUsername == null || actorUsername.isBlank()) return Optional.empty();
        Optional<User> opt = userRepository.findByUsername(actorUsername.trim());
        if (opt.isEmpty()) return Optional.empty();
        String role = opt.get().getRole() != null ? opt.get().getRole().toUpperCase() : "";
        if (!"ADMIN".equals(role) && !"SUPER_ADMIN".equals(role)) return Optional.empty();
        return opt;
    }

    // -------------------------------------------------------------------------
    // SUMMARY
    // -------------------------------------------------------------------------
    @GetMapping("/summary")
    public Map<String, Object> summary(@RequestParam(required = false) String actorUsername) {
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
                if ("SUSPICIOUS".equalsIgnoreCase(t.getStatus()) && !t.isFalsePositive()) {
                    flaggedTx++;
                }
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

    // -------------------------------------------------------------------------
    // LIST USERS (with detection pressure)
    // -------------------------------------------------------------------------
    @GetMapping
    public List<Map<String, Object>> list() {
        List<Map<String, Object>> rows = new ArrayList<>();
        try {
            List<User> users = userRepository.findAll();
            List<Transaction> txs = transactionRepository.findAll();
            LocalDateTime now = LocalDateTime.now();

            for (User u : users) {
                if (u == null) continue;

                long total = 0, flagged = 0, cleared = 0;
                int maxRisk = 0;
                String acc = u.getAccountNumber();

                for (Transaction t : txs) {
                    if (t == null) continue;
                    String tAcc = t.getAccountNumber();
                    if (acc != null && acc.equals(tAcc)) {
                        total++;
                        int risk = t.getRiskScore();
                        if (risk > maxRisk) maxRisk = risk;
                        if ("SUSPICIOUS".equalsIgnoreCase(t.getStatus()) && !t.isFalsePositive()) {
                            flagged++;
                        } else {
                            cleared++;
                        }
                    }
                }

                double flaggedRate = total > 0 ? (flagged * 100.0 / total) : 0.0;

                boolean locked = u.getLockoutUntil() != null && u.getLockoutUntil().isAfter(now);
                String activity = "INACTIVE";
                if (u.getLastLoginAt() != null) {
                    if (u.getLastLoginAt().isAfter(now.minusHours(24))) activity = "ACTIVE_24H";
                    else if (u.getLastLoginAt().isAfter(now.minusDays(7))) activity = "ACTIVE_7D";
                }

                String riskBand = "NONE";
                if (flagged >= 5 || flaggedRate >= 40 || maxRisk >= 75) riskBand = "HIGH";
                else if (flagged >= 2 || flaggedRate >= 20 || maxRisk >= 50) riskBand = "MEDIUM";
                else if (flagged >= 1) riskBand = "LOW";

                Map<String, Object> row = new LinkedHashMap<>();
                row.put("id", u.getId());
                row.put("username", u.getUsername());
                row.put("email", u.getEmail());
                row.put("fullName", u.getFullName());
                row.put("role", u.getRole());
                row.put("accountNumber", u.getAccountNumber());
                row.put("failedAttempts", u.getFailedAttempts());
                row.put("lockoutLevel", u.getLockoutLevel());
                row.put("locked", locked);
                row.put("lockoutUntil", u.getLockoutUntil() != null ? u.getLockoutUntil().toString() : null);
                row.put("createdAt", u.getCreatedAt() != null ? u.getCreatedAt().toString() : null);
                row.put("lastLoginAt", u.getLastLoginAt() != null ? u.getLastLoginAt().toString() : null);
                row.put("activity", activity);
                row.put("txTotal", total);
                row.put("txFlagged", flagged);
                row.put("txCleared", cleared);
                row.put("flaggedRate", Math.round(flaggedRate * 10.0) / 10.0);
                row.put("maxRisk", maxRisk);
                row.put("riskBand", riskBand);
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

    // -------------------------------------------------------------------------
    // UNLOCK ACCOUNT
    // -------------------------------------------------------------------------
    @PutMapping("/{id}/unlock")
    public Map<String, Object> unlock(@PathVariable Long id,
                                      @RequestParam(required = false) String actorUsername) {
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
            u.setLockoutLevel(0);
            userRepository.save(u);
            res.put("success", true);
            res.put("message", "Account unlocked: " + u.getUsername());
        } catch (Exception e) {
            res.put("success", false);
            res.put("message", e.getMessage());
        }
        return res;
    }

    // -------------------------------------------------------------------------
    // SUPER ADMIN ONLY — CREATE ADMIN
    // -------------------------------------------------------------------------
    @PostMapping("/admins")
    public ResponseEntity<?> createAdmin(@RequestBody Map<String, String> body,
                                         @RequestParam String actorUsername) {
        if (requireSuperAdmin(actorUsername).isEmpty()) {
            return ResponseEntity.status(403)
                    .body(Map.of("success", false, "message", "Only SuperAdmin can add admin accounts"));
        }

        String username = body.getOrDefault("username", "").trim();
        String email = body.getOrDefault("email", "").trim().toLowerCase();
        String password = body.getOrDefault("password", "");
        String fullName = body.getOrDefault("fullName", "").trim();

        if (username.length() < 4) {
            return ResponseEntity.badRequest()
                    .body(Map.of("success", false, "message", "Username must be at least 4 characters"));
        }
        if (userRepository.existsByUsername(username)) {
            return ResponseEntity.badRequest()
                    .body(Map.of("success", false, "message", "Username already taken"));
        }
        if (email.isEmpty() || !email.contains("@")) {
            return ResponseEntity.badRequest()
                    .body(Map.of("success", false, "message", "Valid email is required"));
        }
        if (userRepository.existsByEmail(email)) {
            return ResponseEntity.badRequest()
                    .body(Map.of("success", false, "message", "Email already registered"));
        }
        if (password.length() < 8) {
            return ResponseEntity.badRequest()
                    .body(Map.of("success", false, "message", "Password must be at least 8 characters"));
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

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Admin account created",
                "id", admin.getId(),
                "username", admin.getUsername(),
                "email", admin.getEmail()
        ));
    }

    // -------------------------------------------------------------------------
    // SUPER ADMIN ONLY — REMOVE ADMIN
    // -------------------------------------------------------------------------
    @DeleteMapping("/admins/{id}")
    public ResponseEntity<?> removeAdmin(@PathVariable Long id,
                                         @RequestParam String actorUsername) {
        if (requireSuperAdmin(actorUsername).isEmpty()) {
            return ResponseEntity.status(403)
                    .body(Map.of("success", false, "message", "Only SuperAdmin can remove admin accounts"));
        }

        Optional<User> opt = userRepository.findById(id);
        if (opt.isEmpty()) {
            return ResponseEntity.status(404)
                    .body(Map.of("success", false, "message", "User not found"));
        }

        User target = opt.get();
        String role = target.getRole() != null ? target.getRole().toUpperCase() : "";

        if ("SUPER_ADMIN".equals(role)) {
            return ResponseEntity.badRequest()
                    .body(Map.of("success", false, "message", "Cannot remove SuperAdmin"));
        }
        if (!"ADMIN".equals(role)) {
            return ResponseEntity.badRequest()
                    .body(Map.of("success", false, "message", "Target is not an admin account"));
        }

        userRepository.delete(target);
        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Admin removed: " + target.getUsername()
        ));
    }

    // -------------------------------------------------------------------------
    // LIST ADMINS ONLY (for SuperAdmin panel)
    // -------------------------------------------------------------------------
    @GetMapping("/admins")
    public ResponseEntity<?> listAdmins(@RequestParam String actorUsername) {
        if (requireSuperAdmin(actorUsername).isEmpty()) {
            return ResponseEntity.status(403)
                    .body(Map.of("success", false, "message", "Only SuperAdmin can list admins"));
        }

        List<Map<String, Object>> rows = new ArrayList<>();
        for (User u : userRepository.findAll()) {
            if (u == null) continue;
            String role = u.getRole() != null ? u.getRole().toUpperCase() : "";
            if (!"ADMIN".equals(role) && !"SUPER_ADMIN".equals(role)) continue;

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", u.getId());
            row.put("username", u.getUsername());
            row.put("email", u.getEmail());
            row.put("fullName", u.getFullName());
            row.put("role", u.getRole());
            row.put("createdAt", u.getCreatedAt() != null ? u.getCreatedAt().toString() : null);
            row.put("lastLoginAt", u.getLastLoginAt() != null ? u.getLastLoginAt().toString() : null);
            rows.add(row);
        }
        return ResponseEntity.ok(rows);
    }
}