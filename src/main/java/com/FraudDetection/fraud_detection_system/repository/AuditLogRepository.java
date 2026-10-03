package com.FraudDetection.fraud_detection_system.repository;

import com.FraudDetection.fraud_detection_system.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    List<AuditLog> findTop100ByOrderByTimestampDesc();
}
