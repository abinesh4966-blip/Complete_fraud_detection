package com.FraudDetection.fraud_detection_system.service;

import com.FraudDetection.fraud_detection_system.model.AuditLog;
import com.FraudDetection.fraud_detection_system.repository.AuditLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuditService {

    @Autowired
    private AuditLogRepository auditLogRepository;

    public void log(String actor, String role, String action, String detail) {
        try {
            auditLogRepository.save(new AuditLog(
                    actor != null ? actor : "system",
                    role != null ? role : "-",
                    action,
                    detail != null && detail.length() > 900 ? detail.substring(0, 900) : detail
            ));
        } catch (Exception e) {
            System.out.println("[AUDIT] failed: " + e.getMessage());
        }
    }

    public List<AuditLog> recent() {
        return auditLogRepository.findTop100ByOrderByTimestampDesc();
    }
}
