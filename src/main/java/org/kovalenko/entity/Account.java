package org.kovalenko.entity;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "accounts")
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "phone_number", unique = true, nullable = false)
    private String phoneNumber;

    @Column(name = "password_hash")
    private String passwordHash;

    @Column(name = "totp_secret")
    private String totpSecret;

    @Column(name = "is_2fa_enabled")
    private boolean is2faEnabled = false;

    @Column(name = "is_verified")
    private boolean isVerified = false;

    @Column(name = "otp_code")
    private String otpCode;

    @Column(name = "otp_expires_at")
    private LocalDateTime otpExpiresAt;

    @Column(name = "pin_hash")
    private String pinHash;

    @Column(name = "pin_last_asked_at")
    private LocalDateTime pinLastAskedAt;

    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();
}
