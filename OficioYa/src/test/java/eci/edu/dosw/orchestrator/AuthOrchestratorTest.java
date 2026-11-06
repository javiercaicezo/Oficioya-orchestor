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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
        return new UserDto(7L, "Ana", CORREO, Set.of(Role.WORKER, Role.CLIENT), activo);
    }

    private RegisterRequest solicitudDeRegistro(Set<Role> roles) {
        return new RegisterRequest("Ana", CORREO, CLAVE, roles);
    }

    // ---------- login ----------

    @Test
    void loginExitosoDevuelveElTokenConIdYRoles() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));
        when(jwtProvider.generateToken(7L, List.of("CLIENT", "WORKER"))).thenReturn("token-abc");
        when(jwtProvider.getExpirationSeconds()).thenReturn(1800L);

        LoginResponse respuesta = orchestrator.login(new LoginRequest(CORREO, CLAVE));

        assertEquals("token-abc", respuesta.token());
        assertEquals(1800L, respuesta.expiresInSeconds());
        assertEquals(7L, respuesta.userId());
        assertEquals(Set.of(Role.CLIENT, Role.WORKER), respuesta.roles());
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
        UserDto creado = new UserDto(9L, "Ana", CORREO, Set.of(Role.CLIENT), true);
        when(userService.findByEmail(CORREO)).thenReturn(Optional.empty());
        when(userService.createProfile(any(NewUser.class))).thenReturn(creado);

        UserDto resultado = orchestrator.register(solicitudDeRegistro(Set.of(Role.CLIENT)));

        assertEquals(creado, resultado);
        ArgumentCaptor<NewUser> captor = ArgumentCaptor.forClass(NewUser.class);
        verify(userService).createProfile(captor.capture());
        assertEquals("Ana", captor.getValue().name());
        assertEquals(CORREO, captor.getValue().email());
        assertEquals(Set.of(Role.CLIENT), captor.getValue().roles());
        verify(passwordPolicy).validate(CLAVE);
        verify(credentialService).create(9L, CLAVE);
    }

    @Test
    void registroNoPermiteElRolAdministrador() {
        assertThrows(ForbiddenRoleException.class,
                () -> orchestrator.register(solicitudDeRegistro(Set.of(Role.CLIENT, Role.ADMINISTRATOR))));

        verify(userService, never()).createProfile(any());
        verify(passwordPolicy, never()).validate(any());
    }

    @Test
    void registroConContrasenaDebilNoCreaNada() {
        doThrow(new WeakPasswordException()).when(passwordPolicy).validate(CLAVE);

        assertThrows(WeakPasswordException.class,
                () -> orchestrator.register(solicitudDeRegistro(Set.of(Role.CLIENT))));

        verify(userService, never()).createProfile(any());
        verify(credentialService, never()).create(any(), any());
    }

    @Test
    void registroConCorreoRepetidoNoCreaNada() {
        when(userService.findByEmail(CORREO)).thenReturn(Optional.of(usuario(true)));

        assertThrows(DuplicateUserException.class,
                () -> orchestrator.register(solicitudDeRegistro(Set.of(Role.CLIENT))));

        verify(userService, never()).createProfile(any());
        verify(credentialService, never()).create(any(), any());
    }

    @Test
    void siFallaLaCredencialSeBorraElPerfilCreado() {
        UserDto creado = new UserDto(9L, "Ana", CORREO, Set.of(Role.CLIENT), true);
        when(userService.findByEmail(CORREO)).thenReturn(Optional.empty());
        when(userService.createProfile(any(NewUser.class))).thenReturn(creado);
        RuntimeException fallo = new RuntimeException("base de datos caida");
        doThrow(fallo).when(credentialService).create(9L, CLAVE);

        RuntimeException lanzada = assertThrows(RuntimeException.class,
                () -> orchestrator.register(solicitudDeRegistro(Set.of(Role.CLIENT))));

        assertEquals(fallo, lanzada);
        verify(userService).deleteProfile(9L);
    }

    @Test
    void siTambienFallaElBorradoSeConservaElErrorOriginal() {
        UserDto creado = new UserDto(9L, "Ana", CORREO, Set.of(Role.CLIENT), true);
        when(userService.findByEmail(CORREO)).thenReturn(Optional.empty());
        when(userService.createProfile(any(NewUser.class))).thenReturn(creado);
        doThrow(new RuntimeException("base de datos caida")).when(credentialService).create(9L, CLAVE);
        doThrow(new IllegalStateException("no se pudo borrar")).when(userService).deleteProfile(9L);

        RuntimeException lanzada = assertThrows(RuntimeException.class,
                () -> orchestrator.register(solicitudDeRegistro(Set.of(Role.CLIENT))));

        assertEquals("base de datos caida", lanzada.getMessage());
        assertEquals(1, lanzada.getSuppressed().length);
    }
}