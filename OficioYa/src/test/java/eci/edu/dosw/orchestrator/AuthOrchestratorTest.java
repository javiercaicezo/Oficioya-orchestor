package eci.edu.dosw.orchestrator;

import eci.edu.dosw.identity.exception.AccountLockedException;
import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.identity.exception.ForbiddenRoleException;
import eci.edu.dosw.identity.exception.InvalidCredentialsException;
import eci.edu.dosw.identity.exception.WeakPasswordException;
import eci.edu.dosw.identity.service.CredentialService;
import eci.edu.dosw.identity.service.JwtProvider;
import eci.edu.dosw.identity.service.OtpService;
import eci.edu.dosw.identity.service.PasswordPolicyService;
import eci.edu.dosw.notification.NotificationService;
import eci.edu.dosw.orchestrator.dto.LoginRequest;
import eci.edu.dosw.orchestrator.dto.LoginResponse;
import eci.edu.dosw.orchestrator.dto.RegisterRequest;
import eci.edu.dosw.user.NewUser;
import eci.edu.dosw.user.Role;
import eci.edu.dosw.user.UserDto;
import eci.edu.dosw.user.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import eci.edu.dosw.identity.exception.InvalidOtpException;
import eci.edu.dosw.identity.exception.OtpRateLimitException;
import eci.edu.dosw.identity.exception.UserNotFoundException;
import eci.edu.dosw.orchestrator.dto.ChangePasswordRequest;
import eci.edu.dosw.orchestrator.dto.ForgotPasswordRequest;
import eci.edu.dosw.orchestrator.dto.ResetPasswordRequest;
import org.mockito.InOrder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Prueba unitaria pura del orquestador: todos los modulos son mocks. */
class AuthOrchestratorTest {

    private static final String CORREO = "ana@x.com";
    private static final String CLAVE = "Segura#Clave2026";

    private UserService userService;
    private NotificationService notificationService;
    private CredentialService credentialService;
    private OtpService otpService;
    private PasswordPolicyService passwordPolicy;
    private JwtProvider jwtProvider;
    private AuthOrchestrator orchestrator;

    @BeforeEach
    void preparar() {
        userService = mock(UserService.class);
        notificationService = mock(NotificationService.class);
        credentialService = mock(CredentialService.class);
        otpService = mock(OtpService.class);
        passwordPolicy = mock(PasswordPolicyService.class);
        jwtProvider = mock(JwtProvider.class);
        orchestrator = new AuthOrchestrator(userService, notificationService, credentialService,
                otpService, passwordPolicy, jwtProvider);
    }

    private UserDto usuario(boolean activo) {
        return new UserDto(7L, "Ana", CORREO, Set.of(Role.TRABAJADOR, Role.CONTRATANTE), activo);
    }

    private RegisterRequest solicitudDeRegistro(Set<Role> roles) {
        return new RegisterRequest("Ana", CORREO, CLAVE, roles);
    }

    // ---------- login ----------

    @Test
    void loginExitosoDevuelveElTokenConIdYRoles() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        when(jwtProvider.generateToken(7L, List.of("CONTRATANTE", "TRABAJADOR"))).thenReturn("token-abc");
        when(jwtProvider.getExpirationSeconds()).thenReturn(900L);

        LoginResponse respuesta = orchestrator.login(new LoginRequest(CORREO, CLAVE));

        assertEquals("token-abc", respuesta.token());
        assertEquals(900L, respuesta.expiresInSeconds());
        assertEquals(7L, respuesta.userId());
        assertEquals(Set.of(Role.CONTRATANTE, Role.TRABAJADOR), respuesta.roles());
        verify(credentialService).authenticate(7L, CLAVE);
    }

    @Test
    void loginConCorreoInexistenteSeRechazaSinVerificarContrasena() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.empty());

        assertThrows(InvalidCredentialsException.class,
                () -> orchestrator.login(new LoginRequest(CORREO, CLAVE)));

        verify(credentialService, never()).authenticate(any(), anyString());
        verify(jwtProvider, never()).generateToken(any(), any());
    }

    @Test
    void loginConUsuarioInactivoDaElMismoMensajeQueUnCorreoInexistente() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(false)));
        String mensajeInactivo = assertThrows(InvalidCredentialsException.class,
                () -> orchestrator.login(new LoginRequest(CORREO, CLAVE))).getMessage();

        when(userService.findByEmail("nadie@x.com")).thenReturn(Optional.empty());
        String mensajeInexistente = assertThrows(InvalidCredentialsException.class,
                () -> orchestrator.login(new LoginRequest("nadie@x.com", CLAVE))).getMessage();

        assertEquals(mensajeInexistente, mensajeInactivo);
        verify(credentialService, never()).authenticate(any(), anyString());
    }

    @Test
    void loginConContrasenaIncorrectaPropagaElErrorYNoEmiteToken() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        doThrow(new InvalidCredentialsException()).when(credentialService).authenticate(7L, "mala");

        assertThrows(InvalidCredentialsException.class,
                () -> orchestrator.login(new LoginRequest(CORREO, "mala")));

        verify(jwtProvider, never()).generateToken(any(), any());
    }

    @Test
    void loginConCuentaBloqueadaPropagaElBloqueo() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        doThrow(new AccountLockedException()).when(credentialService).authenticate(7L, CLAVE);

        assertThrows(AccountLockedException.class,
                () -> orchestrator.login(new LoginRequest(CORREO, CLAVE)));

        verify(jwtProvider, never()).generateToken(any(), any());
    }

    // ---------- register ----------

    @Test
    void registroExitosoCreaElPerfilYLaCredencial() {
        UserDto creado = new UserDto(9L, "Ana", CORREO, Set.of(Role.CONTRATANTE), true);
        when(userService.findByEmail(CORREO)).thenReturn(Optional.empty());
        when(userService.createProfile(any(NewUser.class))).thenReturn(creado);

        UserDto resultado = orchestrator.register(solicitudDeRegistro(Set.of(Role.CONTRATANTE)));

        assertEquals(creado, resultado);
        ArgumentCaptor<NewUser> captor = ArgumentCaptor.forClass(NewUser.class);
        verify(userService).createProfile(captor.capture());
        assertEquals("Ana", captor.getValue().name());
        assertEquals(CORREO, captor.getValue().email());
        assertEquals(Set.of(Role.CONTRATANTE), captor.getValue().roles());
        verify(passwordPolicy).validate(CLAVE);
        verify(credentialService).create(9L, CLAVE);
    }

    @Test
    void registroNoPermiteElRolAdministrador() {
        assertThrows(ForbiddenRoleException.class,
                () -> orchestrator.register(solicitudDeRegistro(Set.of(Role.CONTRATANTE, Role.ADMIN))));

        verify(userService, never()).createProfile(any());
        verify(passwordPolicy, never()).validate(any());
    }

    @Test
    void registroConContrasenaDebilNoCreaNada() {
        doThrow(new WeakPasswordException()).when(passwordPolicy).validate(CLAVE);

        assertThrows(WeakPasswordException.class,
                () -> orchestrator.register(solicitudDeRegistro(Set.of(Role.CONTRATANTE))));

        verify(userService, never()).createProfile(any());
        verify(credentialService, never()).create(any(), any());
    }

    @Test
    void registroConCorreoRepetidoNoCreaNada() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));

        assertThrows(DuplicateUserException.class,
                () -> orchestrator.register(solicitudDeRegistro(Set.of(Role.CONTRATANTE))));

        verify(userService, never()).createProfile(any());
        verify(credentialService, never()).create(any(), any());
    }

    @Test
    void siFallaLaCredencialSeBorraElPerfilCreado() {
        UserDto creado = new UserDto(9L, "Ana", CORREO, Set.of(Role.CONTRATANTE), true);
        when(userService.findByEmail(CORREO)).thenReturn(Optional.empty());
        when(userService.createProfile(any(NewUser.class))).thenReturn(creado);
        RuntimeException fallo = new RuntimeException("base de datos caida");
        doThrow(fallo).when(credentialService).create(9L, CLAVE);

        RuntimeException lanzada = assertThrows(RuntimeException.class,
                () -> orchestrator.register(solicitudDeRegistro(Set.of(Role.CONTRATANTE))));

        assertEquals(fallo, lanzada);
        verify(userService).deleteProfile(9L);
    }

    @Test
    void siTambienFallaElBorradoSeConservaElErrorOriginal() {
        UserDto creado = new UserDto(9L, "Ana", CORREO, Set.of(Role.CONTRATANTE), true);
        when(userService.findByEmail(CORREO)).thenReturn(Optional.empty());
        when(userService.createProfile(any(NewUser.class))).thenReturn(creado);
        doThrow(new RuntimeException("base de datos caida")).when(credentialService).create(9L, CLAVE);
        doThrow(new IllegalStateException("no se pudo borrar")).when(userService).deleteProfile(9L);

        RuntimeException lanzada = assertThrows(RuntimeException.class,
                () -> orchestrator.register(solicitudDeRegistro(Set.of(Role.CONTRATANTE))));

        assertEquals("base de datos caida", lanzada.getMessage());
        assertEquals(1, lanzada.getSuppressed().length);
    }

    // ---------- changePassword ----------

    private static final String ACTUAL = "Actual#Clave2026";
    private static final String NUEVA = "Nueva#Clave2027";

    @Test
    void cambiaLaContrasenaYAvisaPorCorreo() {
        when(userService.findById(7L)).thenReturn(Optional.of(usuario(true)));

        orchestrator.changePassword(7L, new ChangePasswordRequest(ACTUAL, NUEVA));

        verify(credentialService).changePassword(7L, ACTUAL, NUEVA);
        verify(notificationService).sendPasswordChangedNotice(CORREO);
    }

    @Test
    void conLaContrasenaActualIncorrectaNoSeAvisa() {
        when(userService.findById(7L)).thenReturn(Optional.of(usuario(true)));
        doThrow(new InvalidCredentialsException()).when(credentialService).changePassword(7L, "mala", NUEVA);

        assertThrows(InvalidCredentialsException.class,
                () -> orchestrator.changePassword(7L, new ChangePasswordRequest("mala", NUEVA)));

        verify(notificationService, never()).sendPasswordChangedNotice(any());
    }

    @Test
    void cambioDeUnUsuarioInexistenteLanzaNoEncontrado() {
        when(userService.findById(99L)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class,
                () -> orchestrator.changePassword(99L, new ChangePasswordRequest(ACTUAL, NUEVA)));

        verify(credentialService, never()).changePassword(any(), any(), any());
    }

    @Test
    void siFallaElAvisoElCambioDeContrasenaSeMantiene() {
        when(userService.findById(7L)).thenReturn(Optional.of(usuario(true)));
        doThrow(new RuntimeException("correo caido")).when(notificationService).sendPasswordChangedNotice(CORREO);

        assertDoesNotThrow(() -> orchestrator.changePassword(7L, new ChangePasswordRequest(ACTUAL, NUEVA)));

        verify(credentialService).changePassword(7L, ACTUAL, NUEVA);
    }

    // ---------- forgotPassword ----------

    @Test
    void olvidoGeneraElCodigoYLoEnvia() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        when(otpService.generate(7L)).thenReturn("123456");

        orchestrator.forgotPassword(new ForgotPasswordRequest(CORREO));

        verify(notificationService).sendPasswordResetCode(CORREO, "123456", OtpService.VALID_MINUTES);
    }

    @Test
    void olvidoConCorreoInexistenteNoHaceNadaNiLanzaError() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.empty());

        assertDoesNotThrow(() -> orchestrator.forgotPassword(new ForgotPasswordRequest(CORREO)));

        verify(otpService, never()).generate(any());
        verify(notificationService, never()).sendPasswordResetCode(any(), any(), org.mockito.ArgumentMatchers.anyInt());
    }

    @Test
    void olvidoConUsuarioInactivoNoHaceNadaNiLanzaError() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(false)));

        assertDoesNotThrow(() -> orchestrator.forgotPassword(new ForgotPasswordRequest(CORREO)));

        verify(otpService, never()).generate(any());
    }

    @Test
    void alSuperarElLimiteDeSolicitudesNoHayErrorNiSeEnviaCodigo() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        doThrow(new OtpRateLimitException()).when(otpService).generate(7L);

        assertDoesNotThrow(() -> orchestrator.forgotPassword(new ForgotPasswordRequest(CORREO)));

        verify(notificationService, never()).sendPasswordResetCode(any(), any(), org.mockito.ArgumentMatchers.anyInt());
    }

    @Test
    void olvidoConPerfilSinCredencialNoLanzaError() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        doThrow(new UserNotFoundException()).when(otpService).generate(7L);

        assertDoesNotThrow(() -> orchestrator.forgotPassword(new ForgotPasswordRequest(CORREO)));

        verify(notificationService, never()).sendPasswordResetCode(any(), any(), org.mockito.ArgumentMatchers.anyInt());
    }

    // ---------- resetPassword ----------

    @Test
    void restablecerValidaLaClaveLuegoConsumeElCodigoYDespuesCambia() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));

        orchestrator.resetPassword(new ResetPasswordRequest(CORREO, "123456", NUEVA));

        InOrder orden = inOrder(credentialService, otpService);
        orden.verify(credentialService).validateNewPassword(7L, NUEVA);
        orden.verify(otpService).verifyAndConsume(7L, "123456");
        orden.verify(credentialService).resetPassword(7L, NUEVA);
        verify(notificationService).sendPasswordChangedNotice(CORREO);
    }

    @Test
    void conUnaContrasenaNuevaInvalidaNoSeGastaElCodigo() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        doThrow(new WeakPasswordException()).when(credentialService).validateNewPassword(7L, "debil");

        assertThrows(WeakPasswordException.class,
                () -> orchestrator.resetPassword(new ResetPasswordRequest(CORREO, "123456", "debil")));

        verify(otpService, never()).verifyAndConsume(any(), any());
        verify(credentialService, never()).resetPassword(any(), any());
    }

    @Test
    void conUnCodigoIncorrectoNoSeCambiaLaContrasena() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        doThrow(new InvalidOtpException()).when(otpService).verifyAndConsume(7L, "000000");

        assertThrows(InvalidOtpException.class,
                () -> orchestrator.resetPassword(new ResetPasswordRequest(CORREO, "000000", NUEVA)));

        verify(credentialService, never()).resetPassword(any(), any());
        verify(notificationService, never()).sendPasswordChangedNotice(any());
    }

    @Test
    void restablecerConCorreoInexistenteDaCodigoInvalido() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.empty());

        assertThrows(InvalidOtpException.class,
                () -> orchestrator.resetPassword(new ResetPasswordRequest(CORREO, "123456", NUEVA)));

        verify(otpService, never()).verifyAndConsume(any(), any());
    }

    @Test
    void restablecerConUsuarioInactivoDaCodigoInvalido() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(false)));

        assertThrows(InvalidOtpException.class,
                () -> orchestrator.resetPassword(new ResetPasswordRequest(CORREO, "123456", NUEVA)));

        verify(otpService, never()).verifyAndConsume(any(), any());
    }

    @Test
    void restablecerConPerfilSinCredencialDaCodigoInvalido() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        doThrow(new UserNotFoundException()).when(credentialService).validateNewPassword(7L, NUEVA);

        assertThrows(InvalidOtpException.class,
                () -> orchestrator.resetPassword(new ResetPasswordRequest(CORREO, "123456", NUEVA)));

        verify(otpService, never()).verifyAndConsume(any(), any());
    }

    @Test
    void siFallaElAvisoElRestablecimientoSeMantiene() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        doThrow(new RuntimeException("correo caido")).when(notificationService).sendPasswordChangedNotice(CORREO);

        assertDoesNotThrow(() -> orchestrator.resetPassword(new ResetPasswordRequest(CORREO, "123456", NUEVA)));

        verify(credentialService).resetPassword(7L, NUEVA);
    }

}