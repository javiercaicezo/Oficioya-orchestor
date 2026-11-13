package eci.edu.dosw.orchestrator;

import eci.edu.dosw.identity.exception.AccountInactiveException;
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
import eci.edu.dosw.user.UserDto;
import eci.edu.dosw.user.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

/**
 * Coordinates authentication and identity workflows across the User, Identity, and Notification modules
 * (OR-01 through OR-03).
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
     * is active, validates credentials via the Identity module, and issues a signed JWT.
     */
    public LoginResponse login(LoginRequest request) {
        UserDto user = userService.findByEmail(request.email())
                .orElseThrow(InvalidCredentialsException::new);

        if (!user.isActive()) {
            log.warn("Login rechazado para userId={}: cuenta inactiva o bloqueada (accountStatus={})",
                    user.id(), user.accountStatus());
            throw new AccountInactiveException("La cuenta se encuentra inactiva o bloqueada.");
        }

        credentialService.authenticate(user.id(), request.password());

        String token = jwtProvider.generateToken(user.id(), user.roles());
        log.info("Inicio de sesión exitoso para userId={}", user.id());
        return new LoginResponse(token, jwtProvider.getExpirationSeconds(), user.id(), user.roles());
    }

    /**
     * Registers a new user: validates all pre-conditions before creating any entities, creates the user
     * profile in the User domain, and persists credentials in the Identity domain.
     * If credential creation fails, an automated compensating transaction deletes the created profile in Users.
     */
    public UserDto register(RegisterRequest request) {
        if (request.roles() != null) {
            boolean rolProhibido = request.roles().stream()
                    .anyMatch(r -> r.equalsIgnoreCase("ADMIN") || r.equalsIgnoreCase("SERVICE"));
            if (rolProhibido) {
                throw new ForbiddenRoleException();
            }
        }

        passwordPolicy.validate(request.password());

        if (userService.findByEmail(request.email()).isPresent()) {
            throw new DuplicateUserException();
        }

        UserDto creado = userService.createProfile(
                new NewUser(request.name(), request.email(), request.phones(), request.roles()));

        try {
            credentialService.create(creado.id(), creado.email(), request.password());
            log.info("Usuario registrado exitosamente con userId={}", creado.id());
        } catch (RuntimeException e) {
            deshacerPerfil(creado.id(), e);
            throw e;
        }

        return creado;
    }

    /**
     * Changes the password of an authenticated user.
     */
    public void changePassword(UUID userId, ChangePasswordRequest request) {
        UserDto user = userService.findById(userId).orElseThrow(UserNotFoundException::new);

        credentialService.changePassword(userId, request.currentPassword(), request.newPassword());
        log.info("Contraseña actualizada exitosamente para userId={}", userId);

        avisarCambioDeContrasena(user.email());
    }

    /**
     * Initiates the forgotten password workflow.
     */
    public void forgotPassword(ForgotPasswordRequest request) {
        Optional<UserDto> user = userService.findByEmail(request.email()).filter(UserDto::isActive);
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
     * Resets a user's password using a verified OTP.
     */
    public void resetPassword(ResetPasswordRequest request) {
        UserDto user = userService.findByEmail(request.email())
                .filter(UserDto::isActive)
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

    private void avisarCambioDeContrasena(String email) {
        try {
            notificationService.sendPasswordChangedNotice(email);
        } catch (RuntimeException e) {
            log.warn("No se pudo enviar el aviso de cambio de contraseña: {}", e.getMessage());
        }
    }

    private void deshacerPerfil(UUID userId, RuntimeException causa) {
        try {
            userService.deleteProfile(userId);
            log.warn("Compensación ejecutada: perfil eliminado en Users para userId={}", userId);
        } catch (RuntimeException falloAlDeshacer) {
            causa.addSuppressed(falloAlDeshacer);
            log.error("Fallo al compensar perfil para userId={}: {}", userId, falloAlDeshacer.getMessage());
        }
    }
}
