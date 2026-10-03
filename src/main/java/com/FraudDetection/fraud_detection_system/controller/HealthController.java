package com.FraudDetection.fraud_detection_system.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@CrossOrigin(origins = "*")
public class HealthController {

    @GetMapping({"/api/health", "/actuator/health", "/health"})
    public Map<String, Object> health() {
        return Map.of(
                "status", "UP",
                "service", "BSN Fraud Detection System",
                "timestamp", Instant.now().toString()
        );
    }
}
