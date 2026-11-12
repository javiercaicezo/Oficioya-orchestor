package eci.edu.dosw.orchestrator;

import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.identity.exception.ForbiddenRoleException;
import eci.edu.dosw.identity.exception.InvalidCredentialsException;
import eci.edu.dosw.identity.exception.InvalidOtpException;
import eci.edu.dosw.identity.exception.OtpRateLimitException;
import eci.edu.dosw.identity.exception.UserNotFoundException;
import eci.edu.dosw.identity.service.CredentialService;
import eci.edu.dosw.identity.service.JwtProvider;
import eci.edu.dosw.identity.service.OtpService;
import eci.edu.dosw.identity.service.PasswordPolicyService;
import eci.edu.dosw.notification.NotificationService;
import eci.edu.dosw.orchestrator.dto.ChangePasswordRequest;
import eci.edu.dosw.orchestrator.dto.ForgotPasswordRequest;
import eci.edu.dosw.orchestrator.dto.LoginRequest;
import eci.edu.dosw.orchestrator.dto.LoginResponse;
import eci.edu.dosw.orchestrator.dto.RegisterRequest;
import eci.edu.dosw.orchestrator.dto.ResetPasswordRequest;
import eci.edu.dosw.user.NewUser;
import eci.edu.dosw.user.Role;
import eci.edu.dosw.user.UserDto;
import eci.edu.dosw.user.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Coordinates authentication and identity workflows across the User, Identity, and Notification modules
 * (OR-01 through OR-03). Serves as the single orchestrator with knowledge of all modules; domain modules
 * do not invoke each other directly.
 * <p>
 * Security Logging Compliance (RNF-03): Logs record user identifiers (userId) rather than sensitive
 * personal data such as raw emails or passwords.
 * </p>
 */
@Service
public class AuthOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(AuthOrchestrator.class);

    private final UserService userService;
    private final NotificationService notificationService;
    private final CredentialService credentialService;
    private final OtpService otpService;
    private final PasswordPolicyService passwordPolicy;
    private final JwtProvider jwtProvider;

    /**
     * Constructs a new AuthOrchestrator with all necessary collaborating services.
     *
     * @param userService         The user profile service.
     * @param notificationService The notification delivery service.
     * @param credentialService   The credential storage and authentication service.
     * @param otpService          The one-time password management service.
     * @param passwordPolicy      The password complexity validation service.
     * @param jwtProvider         The JSON Web Token generator and validator.
     */
    public AuthOrchestrator(UserService userService,
            NotificationService notificationService,
            CredentialService credentialService,
            OtpService otpService,
            PasswordPolicyService passwordPolicy,
            JwtProvider jwtProvider) {
        this.userService = userService;
        this.notificationService = notificationService;
        this.credentialService = credentialService;
        this.otpService = otpService;
        this.passwordPolicy = passwordPolicy;
        this.jwtProvider = jwtProvider;
    }

    /**
     * Authenticates a user: locates the user profile in the User domain, verifies that the account
     * is active, validates credentials via the Identity module, and issues a signed JWT (RF-01, RF-02, RF-08).
     * All authentication rejections return the same generic message to prevent account enumeration (RNF-07).
     *
     * @param request The login payload containing the user's email and plaintext password.
     * @return A {@link LoginResponse} containing the signed JWT, expiration duration, userId, and assigned roles.
     * @throws InvalidCredentialsException if credentials do not match or the user is not found or inactive.
     */
    public LoginResponse login(LoginRequest request) {
        UserDto user = userService.findByEmail(request.email())
                .orElseThrow(InvalidCredentialsException::new);
        if (!user.active()) {
            throw new InvalidCredentialsException();
        }

        credentialService.authenticate(user.id(), request.password());

        String token = jwtProvider.generateToken(user.id(), nombresDeRoles(user.roles()));
        log.info("Inicio de sesión exitoso para userId={}", user.id());
        return new LoginResponse(token, jwtProvider.getExpirationSeconds(), user.id(), user.roles());
    }

    /**
     * Registers a new user: validates all pre-conditions before creating any entities, creates the user
     * profile in the User domain, and persists credentials in the Identity domain (HU 1.1, OR-02).
     * If credential creation fails, an automated compensating transaction (Saga pattern) deletes the created profile.
     *
     * @param request The registration payload containing name, email, password, and requested roles.
     * @return The created {@link UserDto} profile.
     * @throws ForbiddenRoleException if the registration attempts to request the restricted ADMINISTRATOR role.
     * @throws DuplicateUserException if an account already exists with the specified email.
     * @throws eci.edu.dosw.identity.exception.WeakPasswordException if the password does not satisfy security policies.
     */
    public UserDto register(RegisterRequest request) {
        if (request.roles() != null && request.roles().contains(Role.ADMINISTRATOR)) {
            throw new ForbiddenRoleException();
        }
        passwordPolicy.validate(request.password());
        if (userService.findByEmail(request.email()).isPresent()) {
            throw new DuplicateUserException();
        }

        UserDto creado = userService.createProfile(
                new NewUser(request.name(), request.email(), request.roles()));
        try {
            credentialService.create(creado.id(), request.password());
            log.info("Usuario registrado exitosamente con userId={}", creado.id());
        } catch (RuntimeException e) {
            deshacerPerfil(creado.id(), e);
            throw e;
        }
        return creado;
    }

    /**
     * Changes the password of an authenticated user (RF-04).
     * Verifies the user's current password and validates the new password against policies.
     * Sends an email notification notifying the user that the password was updated.
     *
     * @param userId  The authenticated user ID extracted from the token context.
     * @param request The password change payload containing current and new passwords.
     * @throws UserNotFoundException if no user profile exists for the given ID.
     */
    public void changePassword(Long userId, ChangePasswordRequest request) {
        UserDto user = userService.findById(userId).orElseThrow(UserNotFoundException::new);

        credentialService.changePassword(userId, request.currentPassword(), request.newPassword());
        log.info("Contraseña actualizada exitosamente para userId={}", userId);

        avisarCambioDeContrasena(user.email());
    }

    /**
     * Initiates the forgotten password workflow (RF-05).
     * Generates a 6-digit OTP and delivers it via email if the account exists and is active.
     * Always completes silently without throwing exceptions on non-existent accounts to prevent account enumeration.
     *
     * @param request The forgot password payload containing the target email.
     */
    public void forgotPassword(ForgotPasswordRequest request) {
        Optional<UserDto> user = userService.findByEmail(request.email()).filter(UserDto::active);
        if (user.isEmpty()) {
            return;
        }
        try {
            String code = otpService.generate(user.get().id());
            notificationService.sendPasswordResetCode(user.get().email(), code, OtpService.VALID_MINUTES);
            log.info("Código OTP de restablecimiento generado y enviado para userId={}", user.get().id());
        } catch (UserNotFoundException | OtpRateLimitException e) {
            log.warn("Solicitud de código no atendida para userId={}: {}", user.get().id(), e.getMessage());
        }
    }

    /**
     * Resets a user's password using a verified OTP (RF-05).
     * Validates the new password against security policies prior to consuming the OTP to avoid
     * burning the token on preventable policy validation failures.
     *
     * @param request The reset password payload containing email, OTP code, and the new password.
     * @throws InvalidOtpException if the user is not found, the OTP code is invalid/expired, or attempts are exceeded.
     */
    public void resetPassword(ResetPasswordRequest request) {
        UserDto user = userService.findByEmail(request.email())
                .filter(UserDto::active)
                .orElseThrow(InvalidOtpException::new);

        try {
            credentialService.validateNewPassword(user.id(), request.newPassword());
        } catch (UserNotFoundException e) {
            throw new InvalidOtpException();
        }
        otpService.verifyAndConsume(user.id(), request.code());
        credentialService.resetPassword(user.id(), request.newPassword());
        log.info("Contraseña restablecida exitosamente para userId={}", user.id());

        avisarCambioDeContrasena(user.email());
    }

    /**
     * Sends an email notification informing the user that their password was changed.
     * Fails gracefully to prevent notification issues from aborting the primary transaction.
     *
     * @param email The recipient's email address.
     */
    private void avisarCambioDeContrasena(String email) {
        try {
            notificationService.sendPasswordChangedNotice(email);
        } catch (RuntimeException e) {
            log.warn("No se pudo enviar el aviso de cambio de contraseña: {}", e.getMessage());
        }
    }

    /**
     * Executes compensating rollback logic by deleting the created user profile
     * if credential creation fails during registration (OR-02).
     *
     * @param userId The ID of the user profile to delete.
     * @param causa  The original exception that triggered the compensation.
     */
    private void deshacerPerfil(Long userId, RuntimeException causa) {
        try {
            userService.deleteProfile(userId);
            log.warn("Compensación ejecutada: perfil eliminado para userId={} debido a fallo en credenciales", userId);
        } catch (RuntimeException falloAlDeshacer) {
            causa.addSuppressed(falloAlDeshacer);
            log.error("Fallo al compensar perfil para userId={}: {}", userId, falloAlDeshacer.getMessage());
        }
    }

    /**
     * Maps user role objects to a sorted list of uppercase role names for JWT claims.
     *
     * @param roles The set of {@link Role} enums.
     * @return Sorted list of role names.
     */
    private List<String> nombresDeRoles(Set<Role> roles) {
        return roles.stream().map(Role::name).sorted().toList();
    }
}
