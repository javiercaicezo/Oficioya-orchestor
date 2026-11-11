package eci.edu.dosw.identity.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.LocalDateTime;

/**
 * JPA Entity representing the lifecycle and state of a One-Time Password (OTP).
 * 
 * Security Features:
 * Stores only the cryptographic hash of the OTP ({@code codeHash}), never plain text.
 * Prevents replay attacks via the {@code used} flag.
 * Mitigates brute-force attacks by tracking validation {@code attempts}.
 *  enforces strict time-to-live using {@code createdAt} and {@code expiresAt}. 
 * 
 * Like the Credential entity, {@code userId} acts as a logical reference 
 * rather than a physical foreign key constraint.
 */
@Entity
@Table(name = "otp")
public class Otp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "code_hash", nullable = false)
    private String codeHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "purpose", nullable = false, length = 30)
    private OtpPurpose purpose;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "used", nullable = false)
    private boolean used;

    protected Otp() {
        // requerido por JPA
    }

    public Otp(Long userId, String codeHash, OtpPurpose purpose,
               LocalDateTime createdAt, LocalDateTime expiresAt) {
        this.userId = userId;
        this.codeHash = codeHash;
        this.purpose = purpose;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }

    public Long getId() {
        return id;
    }

    public Long getUserId() {
        return userId;
    }

    public String getCodeHash() {
        return codeHash;
    }

    public OtpPurpose getPurpose() {
        return purpose;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public int getAttempts() {
        return attempts;
    }

    public void setAttempts(int attempts) {
        this.attempts = attempts;
    }

    public boolean isUsed() {
        return used;
    }

    public void setUsed(boolean used) {
        this.used = used;
    }
}
