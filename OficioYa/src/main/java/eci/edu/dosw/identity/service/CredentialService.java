package eci.edu.dosw.identity.service;

import eci.edu.dosw.identity.exception.AccountLockedException;
import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.identity.exception.InvalidCredentialsException;
import eci.edu.dosw.identity.exception.UserNotFoundException;
import eci.edu.dosw.identity.model.Credential;
import eci.edu.dosw.identity.repository.CredentialRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

/**
 * Service managing user credentials: encrypted storage, verification,
 * failed-attempt locking, password changes/resets, and compensation deletion.
 */
@Service
public class CredentialService {

    public static final int MAX_FAILED_ATTEMPTS = 3;
    public static final long LOCK_MINUTES = 15;

    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);

    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicy;
    private final Clock clock;

    public CredentialService(CredentialRepository credentialRepository,
            PasswordEncoder passwordEncoder,
            PasswordPolicyService passwordPolicy,
            Clock clock) {
        this.credentialRepository = credentialRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.clock = clock;
    }

    /**
     * Creates credentials for a new user with a validated and encrypted password.
     */
    @Transactional
    public Credential create(UUID id, String email, String rawPassword) {
        passwordPolicy.validate(rawPassword);
        if (credentialRepository.existsByUserId(id)) {
            throw new DuplicateUserException();
        }
        Credential credential = new Credential(id, email, passwordEncoder.encode(rawPassword), now());
        Credential saved = credentialRepository.save(credential);
        log.info("Credencial creada para userId={}", id);
        return saved;
    }

    @Transactional
    public Credential create(UUID userId, String rawPassword) {
        return create(userId, null, rawPassword);
    }

    /**
     * Authenticates a user against their stored credentials.
     */
    @Transactional(noRollbackFor = { InvalidCredentialsException.class, AccountLockedException.class })
    public Credential authenticate(UUID userId, String rawPassword) {
        Credential credential = verifyCurrentPassword(userId, rawPassword);
        credential.setFailedAttempts(0);
        credential.setLockedUntil(null);
        credential.setLastLogin(now());
        return credentialRepository.save(credential);
    }

    /**
     * Changes the password of an authenticated user after verifying their current password.
     */
    @Transactional(noRollbackFor = { InvalidCredentialsException.class, AccountLockedException.class })
    public void changePassword(UUID userId, String currentPassword, String newPassword) {
        Credential credential = verifyCurrentPassword(userId, currentPassword);
        passwordPolicy.validateChange(newPassword, credential.getPasswordHash());
        applyNewPassword(credential, newPassword);
    }

    /**
     * Resets a user's password following a successful OTP verification.
     */
    @Transactional
    public void resetPassword(UUID userId, String newPassword) {
        Credential credential = credentialRepository.findByUserId(userId)
                .orElseThrow(UserNotFoundException::new);
        passwordPolicy.validateChange(newPassword, credential.getPasswordHash());
        applyNewPassword(credential, newPassword);
    }

    /**
     * Validates a candidate new password against security policies and the current password hash.
     */
    @Transactional(readOnly = true)
    public void validateNewPassword(UUID userId, String newPassword) {
        Credential credential = credentialRepository.findByUserId(userId)
                .orElseThrow(UserNotFoundException::new);
        passwordPolicy.validateChange(newPassword, credential.getPasswordHash());
    }

    /**
     * Checks if a token's issuance timestamp (iat) precedes the user's latest password change.
     */
    @Transactional(readOnly = true)
    public boolean wasIssuedBeforePasswordChange(UUID userId, Instant issuedAt) {
        Optional<Credential> credential = credentialRepository.findByUserId(userId);
        if (credential.isEmpty()) {
            return true;
        }
        LocalDateTime changedAt = credential.get().getPasswordChangedAt();
        if (changedAt == null) {
            return false;
        }
        Instant changed = changedAt.atZone(clock.getZone()).toInstant().truncatedTo(ChronoUnit.SECONDS);
        return issuedAt.isBefore(changed);
    }

    /**
     * Deletes user credentials. Used as a compensating action.
     */
    @Transactional
    public void delete(UUID userId) {
        credentialRepository.deleteByUserId(userId);
        log.info("Credencial eliminada para userId={}", userId);
    }

    public boolean exists(UUID userId) {
        return credentialRepository.existsByUserId(userId);
    }

    private Credential verifyCurrentPassword(UUID userId, String rawPassword) {
        LocalDateTime now = now();
        Credential credential = credentialRepository.findByUserId(userId)
                .orElseThrow(InvalidCredentialsException::new);

        if (credential.getLockedUntil() != null && credential.getLockedUntil().isAfter(now)) {
            throw new AccountLockedException();
        }
        if (rawPassword == null || !passwordEncoder.matches(rawPassword, credential.getPasswordHash())) {
            registerFailedAttempt(credential, now);
            throw new InvalidCredentialsException();
        }
        return credential;
    }

    private void registerFailedAttempt(Credential credential, LocalDateTime now) {
        int attempts = credential.getFailedAttempts() + 1;
        if (attempts >= MAX_FAILED_ATTEMPTS) {
            credential.setLockedUntil(now.plusMinutes(LOCK_MINUTES));
            credential.setFailedAttempts(0);
            log.warn("Cuenta bloqueada temporalmente por {} minutos para userId={}", LOCK_MINUTES, credential.getUserId());
        } else {
            credential.setFailedAttempts(attempts);
            log.warn("Intento de autenticación fallido para userId={}. Intentos acumulados={}", credential.getUserId(), attempts);
        }
        credentialRepository.save(credential);
    }

    private void applyNewPassword(Credential credential, String newPassword) {
        credential.setPasswordHash(passwordEncoder.encode(newPassword));
        credential.setPasswordChangedAt(now());
        credential.setFailedAttempts(0);
        credential.setLockedUntil(null);
        credentialRepository.save(credential);
        log.info("Hash de contraseña actualizado exitosamente para userId={}", credential.getUserId());
    }

    private LocalDateTime now() {
        return LocalDateTime.now(clock);
    }
}
