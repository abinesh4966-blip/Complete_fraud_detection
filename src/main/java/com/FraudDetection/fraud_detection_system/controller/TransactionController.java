package com.FraudDetection.fraud_detection_system.controller;

import com.FraudDetection.fraud_detection_system.model.Transaction;
import com.FraudDetection.fraud_detection_system.service.AuditService;
import com.FraudDetection.fraud_detection_system.service.FraudDetectionService;
import com.FraudDetection.fraud_detection_system.service.IsolationForestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/transactions")
@CrossOrigin(origins = "*")
public class TransactionController {

    @Autowired
    private FraudDetectionService fraudDetectionService;

    @Autowired
    private IsolationForestService isolationForestService;

    @Autowired
    private AuditService auditService;

    @PostMapping("/check")
    public Transaction checkTransaction(@RequestBody Transaction transaction) {
        return fraudDetectionService.checkTransaction(transaction);
    }

    @GetMapping("/history")
    public List<Transaction> getHistory() {
        return fraudDetectionService.getAllTransactions();
    }

    @GetMapping("/my-history")
    public List<Transaction> getMyHistory(@RequestParam String accountNumber) {
        if (accountNumber == null || accountNumber.isBlank()) return List.of();
        return fraudDetectionService.getAllTransactions().stream()
                .filter(t -> t != null && accountNumber.equals(String.valueOf(t.getAccountNumber())))
                .collect(Collectors.toList());
    }

    /** Queue for fraud officers: pending review + open flagged cases */
    @GetMapping("/review-queue")
    public List<Transaction> reviewQueue() {
        return fraudDetectionService.getAllTransactions().stream()
                .filter(t -> t != null && !t.isFalsePositive())
                .filter(t -> "PENDING_REVIEW".equals(t.getStatus()) || "SUSPICIOUS".equals(t.getStatus()))
                .filter(t -> t.getReviewStatus() == null || "OPEN".equals(t.getReviewStatus()))
                .sorted((a, b) -> {
                    int sa = b.getRiskScore() != null ? b.getRiskScore() : 0;
                    int sb = a.getRiskScore() != null ? a.getRiskScore() : 0;
                    return Integer.compare(sa, sb);
                })
                .collect(Collectors.toList());
    }

    @PostMapping("/{id}/review")
    public Map<String, Object> reviewCase(@PathVariable Long id, @RequestBody Map<String, String> body) {
        Map<String, Object> res = new HashMap<>();
        try {
            Transaction tx = fraudDetectionService.getAllTransactions().stream()
                    .filter(t -> t.getId() != null && t.getId().equals(id))
                    .findFirst().orElse(null);
            if (tx == null) {
                res.put("success", false);
                res.put("message", "Transaction not found");
                return res;
            }
            String decision = body.getOrDefault("decision", "").toUpperCase();
            String officer = body.getOrDefault("officer", "officer");
            String note = body.getOrDefault("note", "");

            tx.setReviewedBy(officer);
            tx.setReviewedAt(LocalDateTime.now());
            tx.setReviewNote(note);

            if ("CONFIRMED_FRAUD".equals(decision)) {
                tx.setReviewStatus("CONFIRMED_FRAUD");
                tx.setStatus("SUSPICIOUS");
                tx.setFalsePositive(false);
            } else if ("FALSE_POSITIVE".equals(decision)) {
                tx.setReviewStatus("FALSE_POSITIVE");
                tx.setFalsePositive(true);
            } else if ("CLEARED".equals(decision)) {
                tx.setReviewStatus("CLEARED_BY_OFFICER");
                tx.setStatus("NORMAL");
                tx.setFalsePositive(false);
            } else {
                res.put("success", false);
                res.put("message", "decision must be CONFIRMED_FRAUD, FALSE_POSITIVE, or CLEARED");
                return res;
            }
            fraudDetectionService.saveTransaction(tx);
            auditService.log(officer, "ADMIN", "CASE_REVIEW",
                    "tx=" + id + " decision=" + decision + " note=" + note);
            res.put("success", true);
            res.put("message", "Case updated: " + decision);
            res.put("transaction", tx);
        } catch (Exception e) {
            res.put("success", false);
            res.put("message", e.getMessage());
        }
        return res;
    }

    @GetMapping("/stats")
    public Map<String, Object> getStats() {
        List<Transaction> all = fraudDetectionService.getAllTransactions();
        long total = all.size();
        long normal = 0, pending = 0, suspicious = 0, falsePositive = 0, confirmed = 0;
        for (Transaction t : all) {
            if (t == null) continue;
            if (t.isFalsePositive() || "FALSE_POSITIVE".equals(t.getReviewStatus())) falsePositive++;
            else if ("CONFIRMED_FRAUD".equals(t.getReviewStatus())) confirmed++;
            else if ("NORMAL".equals(t.getStatus())) normal++;
            else if ("PENDING_REVIEW".equals(t.getStatus())) pending++;
            else if ("SUSPICIOUS".equals(t.getStatus())) suspicious++;
        }
        Map<String, Object> stats = new HashMap<>();
        stats.put("total", total);
        stats.put("normal", normal);
        stats.put("pendingReview", pending);
        stats.put("suspicious", suspicious);
        stats.put("falsePositive", falsePositive);
        stats.put("confirmedFraud", confirmed);
        stats.put("falsePositiveRate", total == 0 ? 0 : Math.round(falsePositive * 1000.0 / total) / 10.0);
        stats.put("flagRate", total == 0 ? 0 : Math.round(suspicious * 1000.0 / total) / 10.0);
        return stats;
    }

    @GetMapping("/generate")
    public Transaction generate() {
        return fraudDetectionService.generateRandomTransaction();
    }

    @PostMapping("/upload")
    public Map<String, Object> uploadCsv(@RequestParam("file") MultipartFile file) {
        Map<String, Object> response = new HashMap<>();
        int successCount = 0, errorCount = 0, rowCount = 0;
        final int MAX_CSV = 500;
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream()));
            String line;
            boolean first = true;
            while ((line = reader.readLine()) != null) {
                if (first) { first = false; if (line.toLowerCase().contains("account")) continue; }
                if (line.isBlank()) continue;
                rowCount++;
                if (rowCount > MAX_CSV) { errorCount++; break; }
                try {
                    String[] p = line.split(",");
                    if (p.length < 4) { errorCount++; continue; }
                    Transaction tx = new Transaction();
                    tx.setAccountNumber(p[0].trim());
                    tx.setAmount(Double.parseDouble(p[1].trim()));
                    tx.setTransactionType(p[2].trim());
                    tx.setLocation(p[3].trim());
                    fraudDetectionService.checkTransaction(tx);
                    successCount++;
                } catch (Exception e) { errorCount++; }
            }
            reader.close();
            response.put("success", true);
            response.put("message", "Upload completed");
            response.put("processed", successCount);
            response.put("failed", errorCount);
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "Error reading file: " + e.getMessage());
        }
        return response;
    }

    @PutMapping("/{id}/false-positive")
    public Map<String, Object> markAsFalsePositive(@PathVariable Long id,
                                                   @RequestParam(required = false) String officer) {
        Map<String, Object> response = new HashMap<>();
        try {
            Transaction tx = fraudDetectionService.getAllTransactions().stream()
                    .filter(t -> t.getId() != null && t.getId().equals(id))
                    .findFirst().orElse(null);
            if (tx == null) {
                response.put("success", false);
                response.put("message", "Transaction not found");
                return response;
            }
            tx.setFalsePositive(true);
            tx.setReviewStatus("FALSE_POSITIVE");
            tx.setReviewedBy(officer != null ? officer : "admin");
            tx.setReviewedAt(LocalDateTime.now());
            fraudDetectionService.saveTransaction(tx);
            auditService.log(officer != null ? officer : "admin", "ADMIN", "FALSE_POSITIVE", "tx=" + id);
            response.put("success", true);
            response.put("message", "Marked as False Positive");
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", e.getMessage());
        }
        return response;
    }

    @DeleteMapping("/clear-all")
    public Map<String, Object> clearAll(@RequestParam(required = false) String actor,
                                        @RequestParam(required = false) String role,
                                        @RequestParam(required = false) String confirm) {
        Map<String, Object> res = new HashMap<>();
        if (!"DELETE_ALL_DATA".equals(confirm)) {
            res.put("success", false);
            res.put("message", "Confirmation required. Pass confirm=DELETE_ALL_DATA");
            return res;
        }
        long deleted = fraudDetectionService.clearAllTransactions();
        auditService.log(actor != null ? actor : "unknown", role != null ? role : "ADMIN",
                "RESET_SYSTEM_DATA", "Deleted " + deleted + " transactions and reset ML");
        res.put("success", true);
        res.put("deleted", deleted);
        res.put("message", "All transactions cleared and ML model reset");
        return res;
    }

    @DeleteMapping("/clear-mine")
    public Map<String, Object> clearMine(@RequestParam String accountNumber) {
        Map<String, Object> res = new HashMap<>();
        long deleted = fraudDetectionService.clearAccountTransactions(accountNumber);
        res.put("success", true);
        res.put("deleted", deleted);
        res.put("message", "Cleared " + deleted + " transactions for account " + accountNumber);
        return res;
    }

    @PostMapping("/ml/reset")
    public Map<String, Object> resetMl(@RequestParam(required = false) String actor) {
        isolationForestService.reset();
        auditService.log(actor != null ? actor : "admin", "ADMIN", "ML_RESET", "Isolation Forest cleared");
        Map<String, Object> res = new HashMap<>();
        res.put("success", true);
        res.put("ready", false);
        res.put("trainSize", 0);
        res.put("message", "ML model cleared. Rules-only scoring until you retrain.");
        return res;
    }

    @PostMapping("/ml/retrain")
    public Map<String, Object> retrainMl() {
        Map<String, Object> res = new HashMap<>();
        boolean ok = isolationForestService.retrain();
        res.put("success", ok);
        res.put("ready", isolationForestService.isReady());
        res.put("trainSize", isolationForestService.getTrainSize());
        res.put("lastTrained", isolationForestService.getLastTrained() != null
                ? isolationForestService.getLastTrained().toString() : null);
        res.put("message", ok ? "Isolation Forest retrained" : "Not enough NORMAL data (need ~12+)");
        return res;
    }

    @GetMapping("/ml/status")
    public Map<String, Object> mlStatus() {
        Map<String, Object> res = new HashMap<>();
        res.put("ready", isolationForestService.isReady());
        res.put("trainSize", isolationForestService.getTrainSize());
        res.put("lastTrained", isolationForestService.getLastTrained() != null
                ? isolationForestService.getLastTrained().toString() : null);
        return res;
    }

    @GetMapping("/audit")
    public Object auditLog() {
        return auditService.recent();
    }

    /** Management export for offline reporting */
    @GetMapping(value = "/export/csv", produces = "text/csv")
    public String exportCsv() {
        StringBuilder sb = new StringBuilder();
        sb.append("id,accountNumber,amount,type,location,riskScore,riskLevel,status,reviewStatus,falsePositive,timestamp\n");
        for (Transaction t : fraudDetectionService.getAllTransactions()) {
            if (t == null) continue;
            sb.append(t.getId()).append(',')
              .append(safe(t.getAccountNumber())).append(',')
              .append(t.getAmount()).append(',')
              .append(safe(t.getTransactionType())).append(',')
              .append(safe(t.getLocation())).append(',')
              .append(t.getRiskScore()).append(',')
              .append(safe(t.getRiskLevel())).append(',')
              .append(safe(t.getStatus())).append(',')
              .append(safe(t.getReviewStatus())).append(',')
              .append(t.isFalsePositive()).append(',')
              .append(t.getTimestamp() != null ? t.getTimestamp().toString() : "")
              .append('\n');
        }
        return sb.toString();
    }

    private String safe(String s) {
        if (s == null) return "";
        return "\"" + s.replace("\"", "'") + "\"";
    }
}
