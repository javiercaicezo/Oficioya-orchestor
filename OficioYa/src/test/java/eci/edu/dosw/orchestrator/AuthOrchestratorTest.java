package eci.edu.dosw.orchestrator;

import eci.edu.dosw.identity.exception.AccountInactiveException;
import eci.edu.dosw.identity.exception.AccountLockedException;
import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.identity.exception.ForbiddenRoleException;
import eci.edu.dosw.identity.exception.InvalidCredentialsException;
import eci.edu.dosw.identity.exception.InvalidOtpException;
import eci.edu.dosw.identity.exception.OtpRateLimitException;
import eci.edu.dosw.identity.exception.UserNotFoundException;
import eci.edu.dosw.identity.exception.WeakPasswordException;
import eci.edu.dosw.identity.service.CredentialService;
import eci.edu.dosw.identity.service.JwtProvider;
import eci.edu.dosw.identity.service.OtpService;
import eci.edu.dosw.identity.service.PasswordPolicyService;
import eci.edu.dosw.notification.NotificationService;
import eci.edu.dosw.orchestrator.dto.ChangePasswordRequest;
import eci.edu.dosw.orchestrator.dto.ForgotPasswordRequest;
import eci.edu.dosw.orchestrator.dto.LoginRequest;
import eci.edu.dosw.orchestrator.dto.LoginResponse;
import eci.edu.dosw.orchestrator.dto.PhoneDTO;
import eci.edu.dosw.orchestrator.dto.RegisterRequest;
import eci.edu.dosw.orchestrator.dto.ResetPasswordRequest;
import eci.edu.dosw.user.NewUser;
import eci.edu.dosw.user.UserDto;
import eci.edu.dosw.user.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Prueba unitaria pura del orquestador: todos los modulos son mocks. */
class AuthOrchestratorTest {

    private static final String CORREO = "ana@x.com";
    private static final String CLAVE = "Segura#Clave2026";
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000007");
    private static final UUID USER_ID_9 = UUID.fromString("00000000-0000-0000-0000-000000000009");
    private static final UUID USER_ID_99 = UUID.fromString("00000000-0000-0000-0000-000000000099");

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
        return new UserDto(USER_ID, "Ana", CORREO, List.of(new PhoneDTO("+573001234567", true)),
                List.of("CONTRATANTE", "TRABAJADOR"), activo ? "ACTIVE" : "INACTIVE", activo);
    }

    private RegisterRequest solicitudDeRegistro(List<String> roles) {
        return new RegisterRequest("Ana", CORREO, CLAVE,
                List.of(new PhoneDTO("+573001234567", true)), roles);
    }

    // ---------- login ----------

    @Test
    void loginExitosoDevuelveElTokenConIdYRoles() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        when(jwtProvider.generateToken(USER_ID, List.of("CONTRATANTE", "TRABAJADOR"))).thenReturn("token-abc");
        when(jwtProvider.getExpirationSeconds()).thenReturn(900L);

        LoginResponse respuesta = orchestrator.login(new LoginRequest(CORREO, CLAVE));

        assertEquals("token-abc", respuesta.token());
        assertEquals(900L, respuesta.expiresInSeconds());
        assertEquals(USER_ID, respuesta.userId());
        assertEquals(List.of("CONTRATANTE", "TRABAJADOR"), respuesta.roles());
        verify(credentialService).authenticate(USER_ID, CLAVE);
    }

    @Test
    void loginConCorreoInexistenteSeRechazaSinVerificarContrasena() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.empty());

        assertThrows(InvalidCredentialsException.class,
                () -> orchestrator.login(new LoginRequest(CORREO, CLAVE)));

        verify(credentialService, never()).authenticate(any(), anyString());
        verify(jwtProvider, never()).generateToken(any(UUID.class), any());
    }

    @Test
    void loginConUsuarioInactivoLanzaAccountInactiveException() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(false)));

        assertThrows(AccountInactiveException.class,
                () -> orchestrator.login(new LoginRequest(CORREO, CLAVE)));

        verify(credentialService, never()).authenticate(any(), anyString());
        verify(jwtProvider, never()).generateToken(any(UUID.class), any());
    }

    @Test
    void loginConContrasenaIncorrectaPropagaElErrorYNoEmiteToken() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        doThrow(new InvalidCredentialsException()).when(credentialService).authenticate(USER_ID, "mala");

        assertThrows(InvalidCredentialsException.class,
                () -> orchestrator.login(new LoginRequest(CORREO, "mala")));

        verify(jwtProvider, never()).generateToken(any(UUID.class), any());
    }

    @Test
    void loginConCuentaBloqueadaPropagaElBloqueo() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        doThrow(new AccountLockedException()).when(credentialService).authenticate(USER_ID, CLAVE);

        assertThrows(AccountLockedException.class,
                () -> orchestrator.login(new LoginRequest(CORREO, CLAVE)));

        verify(jwtProvider, never()).generateToken(any(UUID.class), any());
    }

    // ---------- register ----------

    @Test
    void registroExitosoCreaElPerfilYLaCredencial() {
        UserDto creado = new UserDto(USER_ID_9, "Ana", CORREO,
                List.of(new PhoneDTO("+573001234567", true)), List.of("CONTRATANTE"), "ACTIVE");
        when(userService.findByEmail(CORREO)).thenReturn(Optional.empty());
        when(userService.createProfile(any(NewUser.class))).thenReturn(creado);

        UserDto resultado = orchestrator.register(solicitudDeRegistro(List.of("CONTRATANTE")));

        assertEquals(creado, resultado);
        ArgumentCaptor<NewUser> captor = ArgumentCaptor.forClass(NewUser.class);
        verify(userService).createProfile(captor.capture());
        assertEquals("Ana", captor.getValue().name());
        assertEquals(CORREO, captor.getValue().email());
        assertEquals(List.of("CONTRATANTE"), captor.getValue().roles());
        verify(passwordPolicy).validate(CLAVE);
        verify(credentialService).create(USER_ID_9, CORREO, CLAVE);
    }

    @Test
    void registroNoPermiteElRolAdministradorOService() {
        assertThrows(ForbiddenRoleException.class,
                () -> orchestrator.register(solicitudDeRegistro(List.of("CONTRATANTE", "ADMIN"))));
        assertThrows(ForbiddenRoleException.class,
                () -> orchestrator.register(solicitudDeRegistro(List.of("SERVICE"))));

        verify(userService, never()).createProfile(any());
        verify(passwordPolicy, never()).validate(any());
    }

    @Test
    void registroConContrasenaDebilNoCreaNada() {
        doThrow(new WeakPasswordException()).when(passwordPolicy).validate(CLAVE);

        assertThrows(WeakPasswordException.class,
                () -> orchestrator.register(solicitudDeRegistro(List.of("CONTRATANTE"))));

        verify(userService, never()).createProfile(any());
        verify(credentialService, never()).create(any(), any(), any());
    }

    @Test
    void registroConCorreoRepetidoNoCreaNada() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));

        assertThrows(DuplicateUserException.class,
                () -> orchestrator.register(solicitudDeRegistro(List.of("CONTRATANTE"))));

        verify(userService, never()).createProfile(any());
        verify(credentialService, never()).create(any(), any(), any());
    }

    @Test
    void siFallaLaCredencialSeBorraElPerfilCreado() {
        UserDto creado = new UserDto(USER_ID_9, "Ana", CORREO,
                List.of(new PhoneDTO("+573001234567", true)), List.of("CONTRATANTE"), "ACTIVE");
        when(userService.findByEmail(CORREO)).thenReturn(Optional.empty());
        when(userService.createProfile(any(NewUser.class))).thenReturn(creado);
        RuntimeException fallo = new RuntimeException("base de datos caida");
        doThrow(fallo).when(credentialService).create(USER_ID_9, CORREO, CLAVE);

        RuntimeException lanzada = assertThrows(RuntimeException.class,
                () -> orchestrator.register(solicitudDeRegistro(List.of("CONTRATANTE"))));

        assertEquals(fallo, lanzada);
        verify(userService).deleteProfile(USER_ID_9);
    }

    @Test
    void siTambienFallaElBorradoSeConservaElErrorOriginal() {
        UserDto creado = new UserDto(USER_ID_9, "Ana", CORREO,
                List.of(new PhoneDTO("+573001234567", true)), List.of("CONTRATANTE"), "ACTIVE");
        when(userService.findByEmail(CORREO)).thenReturn(Optional.empty());
        when(userService.createProfile(any(NewUser.class))).thenReturn(creado);
        doThrow(new RuntimeException("base de datos caida")).when(credentialService).create(USER_ID_9, CORREO, CLAVE);
        doThrow(new IllegalStateException("no se pudo borrar")).when(userService).deleteProfile(USER_ID_9);

        RuntimeException lanzada = assertThrows(RuntimeException.class,
                () -> orchestrator.register(solicitudDeRegistro(List.of("CONTRATANTE"))));

        assertEquals("base de datos caida", lanzada.getMessage());
        assertEquals(1, lanzada.getSuppressed().length);
    }

    // ---------- changePassword ----------

    private static final String ACTUAL = "Actual#Clave2026";
    private static final String NUEVA = "Nueva#Clave2027";

    @Test
    void cambiaLaContrasenaYAvisaPorCorreo() {
        when(userService.findById(USER_ID)).thenReturn(Optional.of(usuario(true)));

        orchestrator.changePassword(USER_ID, new ChangePasswordRequest(ACTUAL, NUEVA));

        verify(credentialService).changePassword(USER_ID, ACTUAL, NUEVA);
        verify(notificationService).sendPasswordChangedNotice(CORREO);
    }

    @Test
    void conLaContrasenaActualIncorrectaNoSeAvisa() {
        when(userService.findById(USER_ID)).thenReturn(Optional.of(usuario(true)));
        doThrow(new InvalidCredentialsException()).when(credentialService).changePassword(USER_ID, "mala", NUEVA);

        assertThrows(InvalidCredentialsException.class,
                () -> orchestrator.changePassword(USER_ID, new ChangePasswordRequest("mala", NUEVA)));

        verify(notificationService, never()).sendPasswordChangedNotice(any());
    }

    @Test
    void cambioDeUnUsuarioInexistenteLanzaNoEncontrado() {
        when(userService.findById(USER_ID_99)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class,
                () -> orchestrator.changePassword(USER_ID_99, new ChangePasswordRequest(ACTUAL, NUEVA)));

        verify(credentialService, never()).changePassword(any(), any(), any());
    }

    @Test
    void siFallaElAvisoElCambioDeContrasenaSeMantiene() {
        when(userService.findById(USER_ID)).thenReturn(Optional.of(usuario(true)));
        doThrow(new RuntimeException("correo caido")).when(notificationService).sendPasswordChangedNotice(CORREO);

        assertDoesNotThrow(() -> orchestrator.changePassword(USER_ID, new ChangePasswordRequest(ACTUAL, NUEVA)));

        verify(credentialService).changePassword(USER_ID, ACTUAL, NUEVA);
    }

    // ---------- forgotPassword ----------

    @Test
    void olvidoGeneraElCodigoYLoEnvia() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        when(otpService.generate(USER_ID)).thenReturn("123456");

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
        doThrow(new OtpRateLimitException()).when(otpService).generate(USER_ID);

        assertDoesNotThrow(() -> orchestrator.forgotPassword(new ForgotPasswordRequest(CORREO)));

        verify(notificationService, never()).sendPasswordResetCode(any(), any(), org.mockito.ArgumentMatchers.anyInt());
    }

    @Test
    void olvidoConPerfilSinCredencialNoLanzaError() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        doThrow(new UserNotFoundException()).when(otpService).generate(USER_ID);

        assertDoesNotThrow(() -> orchestrator.forgotPassword(new ForgotPasswordRequest(CORREO)));

        verify(notificationService, never()).sendPasswordResetCode(any(), any(), org.mockito.ArgumentMatchers.anyInt());
    }

    // ---------- resetPassword ----------

    @Test
    void restablecerValidaLaClaveLuegoConsumeElCodigoYDespuesCambia() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));

        orchestrator.resetPassword(new ResetPasswordRequest(CORREO, "123456", NUEVA));

        InOrder orden = inOrder(credentialService, otpService);
        orden.verify(credentialService).validateNewPassword(USER_ID, NUEVA);
        orden.verify(otpService).verifyAndConsume(USER_ID, "123456");
        orden.verify(credentialService).resetPassword(USER_ID, NUEVA);
        verify(notificationService).sendPasswordChangedNotice(CORREO);
    }

    @Test
    void conUnaContrasenaNuevaInvalidaNoSeGastaElCodigo() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        doThrow(new WeakPasswordException()).when(credentialService).validateNewPassword(USER_ID, "debil");

        assertThrows(WeakPasswordException.class,
                () -> orchestrator.resetPassword(new ResetPasswordRequest(CORREO, "123456", "debil")));

        verify(otpService, never()).verifyAndConsume(any(), any());
        verify(credentialService, never()).resetPassword(any(), any());
    }

    @Test
    void conUnCodigoIncorrectoNoSeCambiaLaContrasena() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        doThrow(new InvalidOtpException()).when(otpService).verifyAndConsume(USER_ID, "000000");

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
        doThrow(new UserNotFoundException()).when(credentialService).validateNewPassword(USER_ID, NUEVA);

        assertThrows(InvalidOtpException.class,
                () -> orchestrator.resetPassword(new ResetPasswordRequest(CORREO, "123456", NUEVA)));

        verify(otpService, never()).verifyAndConsume(any(), any());
    }

    @Test
    void siFallaElAvisoElRestablecimientoSeMantiene() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        doThrow(new RuntimeException("correo caido")).when(notificationService).sendPasswordChangedNotice(CORREO);

        assertDoesNotThrow(() -> orchestrator.resetPassword(new ResetPasswordRequest(CORREO, "123456", NUEVA)));

        verify(credentialService).resetPassword(USER_ID, NUEVA);
    }

}