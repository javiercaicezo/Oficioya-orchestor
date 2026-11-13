package eci.edu.dosw.identity.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * JPA Entity representing a user's security credentials and authentication state.
 * 
 * <p>Architecture Note: This entity maintains strict domain isolation. The {@code userId} 
 * field acts as a logical reference to the User Domain without enforcing a physical 
 * database foreign key constraint, adhering to Bounded Context principles.</p>
 * 
 * <p>It stores the cryptographically secure {@code passwordHash} and tracks security 
 * metrics such as failed login attempts and temporary account locks to prevent 
 * brute-force attacks.</p>
 */
@Entity
@Table(name = "credential")
public class Credential {

    @Id
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "user_id", nullable = false, unique = true)
    private UUID userId;

    @Column(name = "email")
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    @Column(name = "password_changed_at")
    private LocalDateTime passwordChangedAt;

    protected Credential() {
        // requerido por JPA
    }

    public Credential(UUID userId, String passwordHash, LocalDateTime passwordChangedAt) {
        this(UUID.randomUUID(), userId, null, passwordHash, passwordChangedAt);
    }

    public Credential(UUID userId, String email, String passwordHash, LocalDateTime passwordChangedAt) {
        this(UUID.randomUUID(), userId, email, passwordHash, passwordChangedAt);
    }

    public Credential(UUID id, UUID userId, String email, String passwordHash, LocalDateTime passwordChangedAt) {
        this.id = id != null ? id : UUID.randomUUID();
        this.userId = userId != null ? userId : this.id;
        this.email = email;
        this.passwordHash = passwordHash;
        this.passwordChangedAt = passwordChangedAt;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
        if (this.userId == null) {
            this.userId = id;
        }
    }

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
        if (this.id == null) {
            this.id = userId;
        }
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    public LocalDateTime getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(LocalDateTime lockedUntil) {
        this.lockedUntil = lockedUntil;
    }

    public LocalDateTime getLastLogin() {
        return lastLogin;
    }

    public void setLastLogin(LocalDateTime lastLogin) {
        this.lastLogin = lastLogin;
    }

    public LocalDateTime getPasswordChangedAt() {
        return passwordChangedAt;
    }

    public void setPasswordChangedAt(LocalDateTime passwordChangedAt) {
        this.passwordChangedAt = passwordChangedAt;
    }
}
