package com.FraudDetection.fraud_detection_system.repository;

import com.FraudDetection.fraud_detection_system.model.CustomerReport;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface CustomerReportRepository extends JpaRepository<CustomerReport, Long> {
    List<CustomerReport> findByUsernameOrderByCreatedAtDesc(String username);
    List<CustomerReport> findAllByOrderByCreatedAtDesc();
    List<CustomerReport> findByAssignedToOrderByCreatedAtDesc(String assignedTo);
}
