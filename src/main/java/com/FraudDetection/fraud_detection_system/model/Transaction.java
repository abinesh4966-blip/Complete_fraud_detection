package com.FraudDetection.fraud_detection_system.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "transactions")
public class Transaction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String accountNumber;
    private Double amount;
    private String transactionType;
    private String location;
    private LocalDateTime timestamp;
    private Integer riskScore;

    /** NORMAL | PENDING_REVIEW | SUSPICIOUS */
    private String status;

    /** LOW | MODERATE | HIGH | CRITICAL */
    private String riskLevel;

    private boolean falsePositive = false;

    /** OPEN | CONFIRMED_FRAUD | FALSE_POSITIVE | CLEARED_BY_OFFICER */
    private String reviewStatus = "OPEN";

    private String reviewedBy;
    private LocalDateTime reviewedAt;
    private String reviewNote;

    /** JSON array of reason strings (persisted for audit/explainability) */
    @Column(length = 4000)
    private String reasonsJson;

    @Transient
    private List<String> reasons;

    public Transaction() {}

    public Transaction(String accountNumber, Double amount, String transactionType, String location) {
        this.accountNumber = accountNumber;
        this.amount = amount;
        this.transactionType = transactionType;
        this.location = location;
        this.timestamp = LocalDateTime.now();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getAccountNumber() { return accountNumber; }
    public void setAccountNumber(String accountNumber) { this.accountNumber = accountNumber; }

    public Double getAmount() { return amount; }
    public void setAmount(Double amount) { this.amount = amount; }

    public String getTransactionType() { return transactionType; }
    public void setTransactionType(String transactionType) { this.transactionType = transactionType; }

    public String getLocation() { return location; }
    public void setLocation(String location) { this.location = location; }

    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }

    public Integer getRiskScore() { return riskScore; }
    public void setRiskScore(Integer riskScore) { this.riskScore = riskScore; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public boolean isFalsePositive() { return falsePositive; }
    public void setFalsePositive(boolean falsePositive) { this.falsePositive = falsePositive; }

    public String getReviewStatus() { return reviewStatus; }
    public void setReviewStatus(String reviewStatus) { this.reviewStatus = reviewStatus; }

    public String getReviewedBy() { return reviewedBy; }
    public void setReviewedBy(String reviewedBy) { this.reviewedBy = reviewedBy; }

    public LocalDateTime getReviewedAt() { return reviewedAt; }
    public void setReviewedAt(LocalDateTime reviewedAt) { this.reviewedAt = reviewedAt; }

    public String getReviewNote() { return reviewNote; }
    public void setReviewNote(String reviewNote) { this.reviewNote = reviewNote; }

    public List<String> getReasons() {
        if (reasons != null) return reasons;
        if (reasonsJson == null || reasonsJson.isBlank()) return java.util.List.of();
        try {
            // simple parse: stored as line-separated or JSON-ish
            if (reasonsJson.trim().startsWith("[")) {
                String body = reasonsJson.trim();
                body = body.substring(1, body.length()-1);
                java.util.List<String> out = new java.util.ArrayList<>();
                for (String part : body.split("","")) {
                    String s = part.replace("\"", """).replaceAll("^\s*"|"\s*$", "").trim();
                    if (!s.isEmpty()) out.add(s);
                }
                return out;
            }
            return java.util.Arrays.asList(reasonsJson.split("\|\|"));
        } catch (Exception e) {
            return java.util.List.of(reasonsJson);
        }
    }
    public void setReasons(List<String> reasons) {
        this.reasons = reasons;
        if (reasons == null || reasons.isEmpty()) {
            this.reasonsJson = null;
        } else {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < reasons.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append('"').append(reasons.get(i).replace(""", "'")).append('"');
            }
            sb.append(']');
            this.reasonsJson = sb.toString();
        }
    }
    public String getReasonsJson() { return reasonsJson; }
    public void setReasonsJson(String reasonsJson) { this.reasonsJson = reasonsJson; }
}
