package com.FraudDetection.fraud_detection_system;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Lightweight policy tests (no Spring context) documenting bank decision thresholds.
 */
class RiskPolicyTest {

    private String statusFor(int riskScore) {
        if (riskScore >= 50) return "SUSPICIOUS";
        if (riskScore >= 25) return "PENDING_REVIEW";
        return "NORMAL";
    }

    private String levelFor(int riskScore) {
        if (riskScore >= 75) return "CRITICAL";
        if (riskScore >= 50) return "HIGH";
        if (riskScore >= 25) return "MODERATE";
        return "LOW";
    }

    private int applyAmountFloor(double amount, int score) {
        if (amount >= 25000 && score < 50) return 50;
        if (amount >= 10000 && score < 25) return 25;
        return score;
    }

    @Test
    void lowIsAutoCleared() {
        assertEquals("NORMAL", statusFor(0));
        assertEquals("NORMAL", statusFor(24));
        assertEquals("LOW", levelFor(24));
    }

    @Test
    void moderateRequiresReview() {
        assertEquals("PENDING_REVIEW", statusFor(25));
        assertEquals("PENDING_REVIEW", statusFor(49));
        assertEquals("MODERATE", levelFor(40));
    }

    @Test
    void highIsFlagged() {
        assertEquals("SUSPICIOUS", statusFor(50));
        assertEquals("SUSPICIOUS", statusFor(90));
        assertEquals("HIGH", levelFor(60));
        assertEquals("CRITICAL", levelFor(80));
    }

    @Test
    void largeAmountCannotAutoClear() {
        assertEquals(25, applyAmountFloor(15281.25, 10));
        assertEquals("PENDING_REVIEW", statusFor(applyAmountFloor(15281.25, 10)));
    }

    @Test
    void veryLargeAmountFlagged() {
        assertEquals(50, applyAmountFloor(30000, 20));
        assertEquals("SUSPICIOUS", statusFor(applyAmountFloor(30000, 20)));
    }
}
