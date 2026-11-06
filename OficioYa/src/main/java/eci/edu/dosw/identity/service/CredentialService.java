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
 * Gestiona las credenciales: guardado cifrado, verificacion, bloqueo por
 * intentos fallidos,
 * cambio y restablecimiento de contrasena, y borrado (compensacion de un
 * registro fallido).
 */
@Service
public class CredentialService {

    public static final int MAX_FAILED_ATTEMPTS = 5;
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

    /** Crea la credencial de un usuario con la contrasena validada y cifrada. */
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
     * Verifica usuario y contrasena. Los intentos fallidos deben guardarse aunque
     * se lance la
     * excepcion, por eso noRollbackFor: sin eso, la transaccion los desharia.
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
     * Cambio de contrasena de un usuario autenticado: exige la contrasena actual.
     */
    @Transactional(noRollbackFor = { InvalidCredentialsException.class, AccountLockedException.class })
    public void changePassword(Long userId, String currentPassword, String newPassword) {
        Credential credential = verifyCurrentPassword(userId, currentPassword);
        passwordPolicy.validateChange(newPassword, credential.getPasswordHash());
        applyNewPassword(credential, newPassword);
    }

    /** Restablece la contrasena despues de validar un OTP. No pide la actual. */
    @Transactional
    public void resetPassword(Long userId, String newPassword) {
        Credential credential = credentialRepository.findByUserId(userId)
                .orElseThrow(UserNotFoundException::new);
        passwordPolicy.validateChange(newPassword, credential.getPasswordHash());
        applyNewPassword(credential, newPassword);
    }

    /**
     * Valida la nueva contrasena contra la politica y contra la actual, sin cambiar
     * nada.
     */
    @Transactional(readOnly = true)
    public void validateNewPassword(Long userId, String newPassword) {
        Credential credential = credentialRepository.findByUserId(userId)
                .orElseThrow(UserNotFoundException::new);
        passwordPolicy.validateChange(newPassword, credential.getPasswordHash());
    }

    /**
     * true si el token (iat) se emitió antes del último cambio de contraseña, o si la credencial ya
     * no existe. Un token emitido en el mismo segundo del cambio se considera válido: iat va en
     * segundos y password_changed_at se trunca a segundos para compararlos sin falsos rechazos.
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
     * Borra la credencial. El orquestador lo usa para compensar un registro
     * fallido.
     */
    @Transactional
    public void delete(Long userId) {
        credentialRepository.deleteByUserId(userId);
        log.info("Credencial eliminada para userId={}", userId);
    }

    public boolean exists(Long userId) {
        return credentialRepository.existsByUserId(userId);
    }

    private Credential verifyCurrentPassword(Long userId, String rawPassword) {
        LocalDateTime now = now();
        // Mensaje generico: no revela si el usuario existe o si fallo la contrasena
        // (RNF-07).
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