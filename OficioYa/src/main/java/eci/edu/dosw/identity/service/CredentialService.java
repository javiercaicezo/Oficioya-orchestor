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

/**
 * Core business logic service for credential management.
 * Handles secure storage, authentication verification, password updates, 
 * and enforces security mechanisms such as brute-force lockouts and 
 * time-based session invalidation.
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
     *
     * @param userId      The user's unique identifier.
     * @param rawPassword The plaintext password to be validated and hashed.
     * @return The persisted {@link Credential} entity.
     * @throws DuplicateUserException if credentials already exist for this user.
     */
    @Transactional
    public Credential create(Long userId, String rawPassword) {
        passwordPolicy.validate(rawPassword);
        if (credentialRepository.existsByUserId(userId)) {
            throw new DuplicateUserException();
        }
        Credential credential = new Credential(userId, passwordEncoder.encode(rawPassword), now());
        Credential saved = credentialRepository.save(credential);
        log.info("Credencial creada para userId={}", userId);
        return saved;
    }

    /**
     * Authenticates a user against their stored credentials.
     * 
     * Security Note: The {@code noRollbackFor} configuration ensures that failed 
     * login attempts are persisted to the database to support brute-force prevention, 
     * even when an authentication exception is thrown.
     *
     * @param userId      The logical reference to the user.
     * @param rawPassword The plain text password provided by the client.
     * @return The updated {@link Credential} entity upon successful authentication.
     * @throws InvalidCredentialsException if the user is not found or the password mismatch.
     * @throws AccountLockedException if the user has exceeded the max failed attempts.
     */
    @Transactional(noRollbackFor = { InvalidCredentialsException.class, AccountLockedException.class })
    public Credential authenticate(Long userId, String rawPassword) {
        Credential credential = verifyCurrentPassword(userId, rawPassword);
        credential.setFailedAttempts(0);
        credential.setLockedUntil(null);
        credential.setLastLogin(now());
        return credentialRepository.save(credential);
    }

    /**
     * Changes the password of an authenticated user after verifying their current password.
     *
     * @param userId          The user's unique identifier.
     * @param currentPassword The user's current password for verification.
     * @param newPassword     The new password to set.
     * @throws InvalidCredentialsException if the current password does not match.
     * @throws AccountLockedException      if the account is locked due to excessive failed attempts.
     */
    @Transactional(noRollbackFor = { InvalidCredentialsException.class, AccountLockedException.class })
    public void changePassword(Long userId, String currentPassword, String newPassword) {
        Credential credential = verifyCurrentPassword(userId, currentPassword);
        passwordPolicy.validateChange(newPassword, credential.getPasswordHash());
        applyNewPassword(credential, newPassword);
    }

    /**
     * Resets a user's password following a successful OTP verification.
     * Does not require the current password.
     *
     * @param userId      The user's unique identifier.
     * @param newPassword The new password to set.
     * @throws UserNotFoundException if no credentials exist for the user.
     */
    @Transactional
    public void resetPassword(Long userId, String newPassword) {
        Credential credential = credentialRepository.findByUserId(userId)
                .orElseThrow(UserNotFoundException::new);
        passwordPolicy.validateChange(newPassword, credential.getPasswordHash());
        applyNewPassword(credential, newPassword);
    }

    /**
     * Validates a candidate new password against security policies and the current password hash
     * without modifying the stored credentials.
     *
     * @param userId      The user's unique identifier.
     * @param newPassword The new password to validate.
     * @throws UserNotFoundException if no credentials exist for the user.
     */
    @Transactional(readOnly = true)
    public void validateNewPassword(Long userId, String newPassword) {
        Credential credential = credentialRepository.findByUserId(userId)
                .orElseThrow(UserNotFoundException::new);
        passwordPolicy.validateChange(newPassword, credential.getPasswordHash());
    }

    /**
     * Checks if a token's issuance timestamp (iat) precedes the user's latest password change,
     * or if the credential no longer exists.
     * Tokens issued within the same second as the change are considered valid to avoid false rejections.
     *
     * @param userId   The user's unique identifier.
     * @param issuedAt The instant when the token was issued.
     * @return {@code true} if the token was issued before the last password change or if credentials don't exist;
     *         {@code false} otherwise.
     */
    @Transactional(readOnly = true)
    public boolean wasIssuedBeforePasswordChange(Long userId, Instant issuedAt) {
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
     * Deletes user credentials. Used as a compensating action by the orchestrator
     * in the event of a failed registration workflow.
     *
     * @param userId The unique identifier of the user whose credentials should be removed.
     */
    @Transactional
    public void delete(Long userId) {
        credentialRepository.deleteByUserId(userId);
        log.info("Credencial eliminada para userId={}", userId);
    }

    /**
     * Checks whether credentials exist for a given user.
     *
     * @param userId The unique identifier of the user.
     * @return {@code true} if credentials exist, {@code false} otherwise.
     */
    public boolean exists(Long userId) {
        return credentialRepository.existsByUserId(userId);
    }

    /**
     * Validates the provided password against the stored password hash and verifies
     * that the account is not locked.
     *
     * Note: Uses generic exceptions to prevent user enumeration attacks (RNF-07).
     *
     * @param userId      The user's unique identifier.
     * @param rawPassword The plaintext password to verify.
     * @return The verified {@link Credential} entity.
     * @throws AccountLockedException      if the account is locked due to previous failed attempts.
     * @throws InvalidCredentialsException if the password is incorrect or user credentials are not found.
     */
    private Credential verifyCurrentPassword(Long userId, String rawPassword) {
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

    /**
     * Increments failed login attempts and temporarily locks the account if the threshold is reached.
     *
     * @param credential The credential entity being updated.
     * @param now        The current timestamp.
     */
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

    /**
     * Updates the password hash, updates the password change timestamp, and resets failed attempts and lock status.
     *
     * @param credential  The credential entity being updated.
     * @param newPassword The new plaintext password.
     */
    private void applyNewPassword(Credential credential, String newPassword) {
        credential.setPasswordHash(passwordEncoder.encode(newPassword));
        credential.setPasswordChangedAt(now());
        credential.setFailedAttempts(0);
        credential.setLockedUntil(null);
        credentialRepository.save(credential);
        log.info("Hash de contraseña actualizado exitosamente para userId={}", credential.getUserId());
    }

    /**
     * Returns the current date and time based on the injected clock.
     *
     * @return Current {@link LocalDateTime}.
     */
    private LocalDateTime now() {
        return LocalDateTime.now(clock);
    }
}