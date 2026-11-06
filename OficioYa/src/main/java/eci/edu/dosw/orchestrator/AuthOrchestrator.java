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
 * Coordina los flujos de autenticacion entre los modulos User, Identity y
 * Notification
 * (OR-01 a OR-03). Es el unico que conoce a todos; los modulos no se llaman
 * entre si.
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
     * Login: busca el perfil en User, rechaza si no existe o esta inactivo,
     * verifica la contrasena
     * en Identity y emite el JWT. Todos los rechazos usan el mismo mensaje generico
     * (RF-02, RNF-07).
     */
    public LoginResponse login(LoginRequest request) {
        UserDto user = userService.findByEmail(request.email())
                .orElseThrow(InvalidCredentialsException::new);
        if (!user.active()) {
            throw new InvalidCredentialsException();
        }

        credentialService.authenticate(user.id(), request.password());

        String token = jwtProvider.generateToken(user.id(), nombresDeRoles(user.roles()));
        return new LoginResponse(token, jwtProvider.getExpirationSeconds(), user.id(), user.roles());
    }

    /**
     * Registro: valida todo lo que pueda fallar ANTES de crear nada, crea el perfil
     * en User y luego la
     * credencial en Identity. Si la credencial falla, se compensa borrando el
     * perfil (OR-02).
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
        } catch (RuntimeException e) {
            deshacerPerfil(creado.id(), e);
            throw e;
        }
        return creado;
    }

    /**
     * Cambio de contrasena de un usuario autenticado (RF-04). El id sale del token.
     */
    public void changePassword(Long userId, ChangePasswordRequest request) {
        UserDto user = userService.findById(userId).orElseThrow(UserNotFoundException::new);

        credentialService.changePassword(userId, request.currentPassword(), request.newPassword());

        avisarCambioDeContrasena(user.email());
    }

    /**
     * Olvide mi contrasena (RF-05): genera un OTP y lo envia por correo. La
     * respuesta es siempre la
     * misma, exista o no la cuenta, para no revelar quien esta registrado.
     */
    public void forgotPassword(ForgotPasswordRequest request) {
        Optional<UserDto> user = userService.findByEmail(request.email()).filter(UserDto::active);
        if (user.isEmpty()) {
            return;
        }
        try {
            String code = otpService.generate(user.get().id());
            notificationService.sendPasswordResetCode(user.get().email(), code, OtpService.VALID_MINUTES);
        } catch (UserNotFoundException | OtpRateLimitException e) {
            log.warn("Solicitud de codigo no atendida para el usuario {}: {}", user.get().id(), e.getMessage());
        }
    }

    /**
     * Restablecer contrasena (RF-05): valida primero la contrasena nueva para no
     * gastar el codigo en
     * un error evitable, luego consume el OTP y cambia la contrasena.
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

        avisarCambioDeContrasena(user.email());
    }

    private void avisarCambioDeContrasena(String email) {
        try {
            notificationService.sendPasswordChangedNotice(email);
        } catch (RuntimeException e) {
            log.warn("No se pudo enviar el aviso de cambio de contrasena: {}", e.getMessage());
        }
    }

    private void deshacerPerfil(Long userId, RuntimeException causa) {
        try {
            userService.deleteProfile(userId);
        } catch (RuntimeException falloAlDeshacer) {
            causa.addSuppressed(falloAlDeshacer);
        }
    }

    private List<String> nombresDeRoles(Set<Role> roles) {
        return roles.stream().map(Role::name).sorted().toList();
    }
}