package com.FraudDetection.fraud_detection_system.service;

import com.FraudDetection.fraud_detection_system.model.Transaction;
import com.FraudDetection.fraud_detection_system.model.User;
import com.FraudDetection.fraud_detection_system.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class AlertEmailService {

    @Autowired(required = false)
    private JavaMailSender mailSender;

    @Autowired
    private UserRepository userRepository;

    @Value("${spring.mail.username:}")
    private String mailUsername;

    @Value("${app.mail.from:}")
    private String mailFrom;

    @Value("${app.mail.alert-admins:true}")
    private boolean alertAdmins;

    public boolean isConfigured() {
        return mailSender != null
                && mailUsername != null
                && !mailUsername.isBlank();
    }

    public void sendFraudAlert(Transaction tx) {
        if (tx == null || !"SUSPICIOUS".equalsIgnoreCase(tx.getStatus())) {
            return;
        }

        String subject = "[BSN FDS Alert] Suspicious transaction detected";
        String body = buildBody(tx);

        if (tx.getAccountNumber() != null && !tx.getAccountNumber().isBlank()) {
            Optional<User> owner = userRepository.findByAccountNumber(tx.getAccountNumber());
            if (owner.isPresent()
                    && owner.get().getEmail() != null
                    && !owner.get().getEmail().isBlank()) {
                send(owner.get().getEmail(), subject, body);
            } else {
                System.out.println("[ALERT] No customer email for account " + tx.getAccountNumber());
            }
        }

        if (alertAdmins) {
            List<User> staff = userRepository.findAll().stream()
                    .filter(u -> u.getRole() != null)
                    .filter(u -> {
                        String r = u.getRole().toUpperCase();
                        return "ADMIN".equals(r) || "SUPER_ADMIN".equals(r);
                    })
                    .filter(u -> u.getEmail() != null && !u.getEmail().isBlank())
                    .collect(Collectors.toList());
            for (User admin : staff) {
                send(admin.getEmail(), subject + " (Admin copy)", body);
            }
        }
    }

    private String buildBody(Transaction tx) {
        String reasons = "See dashboard for details";
        List<String> list = tx.getReasons();
        if (list != null && !list.isEmpty()) {
            reasons = list.stream().map(String::valueOf).collect(Collectors.joining("\n- "));
        }

        String riskLevel = tx.getRiskLevel() != null ? tx.getRiskLevel() : "—";
        String time = tx.getTimestamp() != null ? tx.getTimestamp().toString() : "—";

        return "BSN Fraud Detection System — automated alert\n\n"
                + "A transaction was flagged as SUSPICIOUS.\n\n"
                + "Account: " + nullSafe(tx.getAccountNumber()) + "\n"
                + "Amount: RM " + tx.getAmount() + "\n"
                + "Location: " + nullSafe(tx.getLocation()) + "\n"
                + "Type: " + nullSafe(tx.getTransactionType()) + "\n"
                + "Risk score: " + tx.getRiskScore() + "%\n"
                + "Risk level: " + riskLevel + "\n"
                + "Status: " + nullSafe(tx.getStatus()) + "\n"
                + "Time: " + time + "\n\n"
                + "Reasons:\n- " + reasons + "\n\n"
                + "If this was you, mark it as a false positive in the portal or contact support.\n"
                + "This is an academic prototype notification.\n";
    }

    private String nullSafe(String s) {
        return s == null || s.isBlank() ? "—" : s;
    }

    private void send(String to, String subject, String text) {
        if (!isConfigured()) {
            System.out.println("[ALERT EMAIL SKIPPED — mail not configured] To=" + to + " | " + subject);
            System.out.println(text);
            return;
        }
        try {
            SimpleMailMessage msg = new SimpleMailMessage();
            msg.setTo(to);
            msg.setSubject(subject);
            msg.setText(text);
            String from = (mailFrom != null && !mailFrom.isBlank()) ? mailFrom : mailUsername;
            msg.setFrom(from);
            mailSender.send(msg);
            System.out.println("[ALERT EMAIL SENT] To=" + to);
        } catch (Exception e) {
            System.out.println("[ALERT EMAIL FAILED] To=" + to + " | " + e.getMessage());
        }
    }
}
