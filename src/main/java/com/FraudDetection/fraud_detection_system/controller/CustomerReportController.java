package com.FraudDetection.fraud_detection_system.controller;

import com.FraudDetection.fraud_detection_system.model.CustomerReport;
import com.FraudDetection.fraud_detection_system.model.User;
import com.FraudDetection.fraud_detection_system.repository.CustomerReportRepository;
import com.FraudDetection.fraud_detection_system.repository.UserRepository;
import com.FraudDetection.fraud_detection_system.service.AuditService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/reports")
@CrossOrigin(origins = "*")
public class CustomerReportController {

    @Autowired
    private CustomerReportRepository reportRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired(required = false)
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

    private boolean isSuper(User u) {
        return u != null && "SUPER_ADMIN".equalsIgnoreCase(u.getRole());
    }

    private boolean isAdminStaff(User u) {
        if (u == null || u.getRole() == null) return false;
        String r = u.getRole().toUpperCase();
        return r.equals("ADMIN") || r.equals("SUPER_ADMIN");
    }

    @PostMapping("/submit")
    public Map<String, Object> submit(@RequestBody Map<String, String> body) {
        Map<String, Object> res = new HashMap<>();
        try {
            String username = body.getOrDefault("username", "").trim();
            String description = body.getOrDefault("description", "").trim();
            String category = body.getOrDefault("category", "SUSPICIOUS_ACTIVITY").trim();
            if (username.isBlank()) {
                res.put("success", false);
                res.put("message", "Please log in again — username missing");
                return res;
            }
            if (description.length() < 10) {
                res.put("success", false);
                res.put("message", "Please describe the issue (at least 10 characters)");
                return res;
            }
            if (description.length() > 2000) {
                res.put("success", false);
                res.put("message", "Description is too long (max 2000 characters)");
                return res;
            }

            CustomerReport r = new CustomerReport();
            r.setUsername(username);
            r.setAccountNumber(body.getOrDefault("accountNumber", "").trim());
            r.setEmail(body.getOrDefault("email", "").trim());
            r.setCategory(category.isBlank() ? "SUSPICIOUS_ACTIVITY" : category);
            r.setRelatedTxId(body.getOrDefault("relatedTxId", "").trim());
            r.setDescription(description);
            r.setStatus("OPEN");
            r.setCreatedAt(LocalDateTime.now());
            reportRepository.save(r);

            if (auditService != null) {
                auditService.log(username, "USER", "CUSTOMER_REPORT", "Report #" + r.getId() + " submitted");
            }

            res.put("success", true);
            res.put("message", "Report submitted successfully. Reference #" + r.getId());
            res.put("id", r.getId());
        } catch (Exception e) {
            res.put("success", false);
            res.put("message", "Submit failed: " + e.getMessage());
        }
        return res;
    }

    @GetMapping("/mine")
    public List<CustomerReport> mine(@RequestParam String username) {
        if (username == null || username.isBlank()) return List.of();
        return reportRepository.findByUsernameOrderByCreatedAtDesc(username.trim());
    }

    /** SuperAdmin: all. Admin: assigned to them + unassigned open (optional visibility). */
    @GetMapping("/all")
    public List<CustomerReport> all(@RequestParam(required = false) String actorUsername) {
        List<CustomerReport> all = reportRepository.findAllByOrderByCreatedAtDesc();
        if (actorUsername == null || actorUsername.isBlank()) return all;
        Optional<User> actor = findUser(actorUsername);
        if (actor.isEmpty() || isSuper(actor.get())) return all;
        // Regular admin: reports assigned to them, or unassigned
        String name = actor.get().getUsername();
        return all.stream()
                .filter(r -> r.getAssignedTo() == null || r.getAssignedTo().isBlank()
                        || name.equalsIgnoreCase(r.getAssignedTo()))
                .collect(Collectors.toList());
    }

    /** List admins SuperAdmin can assign to */
    @GetMapping("/assignable-admins")
    public List<Map<String, Object>> assignableAdmins() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (User u : userRepository.findAll()) {
            if (u == null || u.getRole() == null) continue;
            String r = u.getRole().toUpperCase();
            if ("ADMIN".equals(r) || "SUPER_ADMIN".equals(r)) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("username", u.getUsername());
                m.put("fullName", u.getFullName());
                m.put("role", u.getRole());
                out.add(m);
            }
        }
        return out;
    }

    /** SuperAdmin pushes report to an admin */
    @PostMapping("/{id}/assign")
    public Map<String, Object> assign(@PathVariable Long id, @RequestBody Map<String, String> body) {
        Map<String, Object> res = new HashMap<>();
        try {
            String actorUsername = body.getOrDefault("actorUsername", "").trim();
            String assignTo = body.getOrDefault("assignTo", "").trim();

            Optional<User> actorOpt = findUser(actorUsername);
            if (actorOpt.isEmpty() || !isSuper(actorOpt.get())) {
                res.put("success", false);
                res.put("message", "Only SuperAdmin can assign reports to admins");
                return res;
            }
            if (assignTo.isBlank()) {
                res.put("success", false);
                res.put("message", "Select an admin to assign");
                return res;
            }

            Optional<User> targetOpt = findUser(assignTo);
            if (targetOpt.isEmpty() || !isAdminStaff(targetOpt.get())) {
                res.put("success", false);
                res.put("message", "Target must be an ADMIN or SUPER_ADMIN account");
                return res;
            }

            Optional<CustomerReport> opt = reportRepository.findById(id);
            if (opt.isEmpty()) {
                res.put("success", false);
                res.put("message", "Report not found");
                return res;
            }

            CustomerReport r = opt.get();
            r.setAssignedTo(targetOpt.get().getUsername());
            r.setAssignedBy(actorOpt.get().getUsername());
            r.setAssignedAt(LocalDateTime.now());
            if ("OPEN".equalsIgnoreCase(r.getStatus())) {
                r.setStatus("IN_REVIEW");
            }
            reportRepository.save(r);

            if (auditService != null) {
                auditService.log(actorUsername, "SUPER_ADMIN", "REPORT_ASSIGN",
                        "Report #" + id + " assigned to " + r.getAssignedTo());
            }

            res.put("success", true);
            res.put("message", "Report #" + id + " assigned to " + r.getAssignedTo());
            res.put("assignedTo", r.getAssignedTo());
            res.put("status", r.getStatus());
        } catch (Exception e) {
            res.put("success", false);
            res.put("message", e.getMessage());
        }
        return res;
    }

    /** Unassign (SuperAdmin) */
    @PostMapping("/{id}/unassign")
    public Map<String, Object> unassign(@PathVariable Long id, @RequestBody Map<String, String> body) {
        Map<String, Object> res = new HashMap<>();
        try {
            String actorUsername = body.getOrDefault("actorUsername", "").trim();
            Optional<User> actorOpt = findUser(actorUsername);
            if (actorOpt.isEmpty() || !isSuper(actorOpt.get())) {
                res.put("success", false);
                res.put("message", "Only SuperAdmin can unassign reports");
                return res;
            }
            Optional<CustomerReport> opt = reportRepository.findById(id);
            if (opt.isEmpty()) {
                res.put("success", false);
                res.put("message", "Report not found");
                return res;
            }
            CustomerReport r = opt.get();
            r.setAssignedTo(null);
            r.setAssignedBy(null);
            r.setAssignedAt(null);
            reportRepository.save(r);
            res.put("success", true);
            res.put("message", "Report #" + id + " unassigned");
        } catch (Exception e) {
            res.put("success", false);
            res.put("message", e.getMessage());
        }
        return res;
    }

    @PostMapping("/{id}/status")
    public Map<String, Object> updateStatus(@PathVariable Long id, @RequestBody Map<String, String> body) {
        Map<String, Object> res = new HashMap<>();
        try {
            Optional<CustomerReport> opt = reportRepository.findById(id);
            if (opt.isEmpty()) {
                res.put("success", false);
                res.put("message", "Report not found");
                return res;
            }
            CustomerReport r = opt.get();
            String status = body.getOrDefault("status", "").trim().toUpperCase();
            if (!List.of("OPEN", "IN_REVIEW", "RESOLVED", "REJECTED").contains(status)) {
                res.put("success", false);
                res.put("message", "Invalid status");
                return res;
            }
            r.setStatus(status);
            r.setReviewedBy(body.getOrDefault("actorUsername", "").trim());
            r.setReviewedAt(LocalDateTime.now());
            String note = body.getOrDefault("adminNote", "");
            if (note != null && !note.isBlank()) r.setAdminNote(note.trim());
            reportRepository.save(r);

            if (auditService != null) {
                auditService.log(r.getReviewedBy(), "ADMIN", "REPORT_STATUS", "Report #" + id + " -> " + status);
            }
            res.put("success", true);
            res.put("message", "Report updated to " + status);
        } catch (Exception e) {
            res.put("success", false);
            res.put("message", e.getMessage());
        }
        return res;
    }
}
