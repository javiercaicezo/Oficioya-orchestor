package eci.edu.dosw.orchestrator;

import eci.edu.dosw.identity.exception.AccountLockedException;
import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.identity.exception.InvalidCredentialsException;
import eci.edu.dosw.identity.exception.InvalidOtpException;
import eci.edu.dosw.identity.repository.CredentialRepository;
import eci.edu.dosw.identity.repository.OtpRepository;
import eci.edu.dosw.identity.service.JwtProvider;
import eci.edu.dosw.local.LocalNotificationService;
import eci.edu.dosw.local.LocalNotificationService.SentMessage;
import eci.edu.dosw.local.LocalUserService;
import eci.edu.dosw.orchestrator.dto.ChangePasswordRequest;
import eci.edu.dosw.orchestrator.dto.ForgotPasswordRequest;
import eci.edu.dosw.orchestrator.dto.LoginRequest;
import eci.edu.dosw.orchestrator.dto.LoginResponse;
import eci.edu.dosw.orchestrator.dto.RegisterRequest;
import eci.edu.dosw.orchestrator.dto.ResetPasswordRequest;
import eci.edu.dosw.user.Role;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Flujos completos con los servicios reales, la base H2 y los stubs locales de
 * User y Notification. No es @Transactional a proposito: asi se comprueba que
 * los intentos fallidos realmente se guardan (noRollbackFor).
 */
@SpringBootTest
@ActiveProfiles("test")
class AuthFlowIntegrationTest {

    private static final String CORREO = "flujo@x.com";
    private static final String CLAVE = "Segura#Clave2026";
    private static final String NUEVA = "Nueva#Clave2027";

    @Autowired
    private AuthOrchestrator orchestrator;
    @Autowired
    private LocalUserService userService;
    @Autowired
    private LocalNotificationService notifications;
    @Autowired
    private CredentialRepository credentialRepository;
    @Autowired
    private OtpRepository otpRepository;
    @Autowired
    private JwtProvider jwtProvider;

    @BeforeEach
    @AfterEach
    void limpiar() {
        credentialRepository.deleteAll();
        otpRepository.deleteAll();
        userService.clear();
        notifications.clear();
    }

    private void registrar() {
        orchestrator.register(new RegisterRequest("Ana", CORREO, CLAVE, Set.of(Role.CONTRATANTE)));
    }

    private String codigoEnviado() {
        return notifications.sentMessages().stream()
                .filter(m -> m.type().equals("RESET_CODE"))
                .map(SentMessage::code)
                .findFirst()
                .orElseThrow();
    }

    @Test
    void registroYLoginEntreganUnTokenValido() {
        registrar();

        LoginResponse respuesta = orchestrator.login(new LoginRequest(CORREO, CLAVE));

        assertTrue(jwtProvider.isValid(respuesta.token()));
        assertEquals(respuesta.userId(), jwtProvider.getUserIdFromToken(respuesta.token()));
        assertEquals(Set.of(Role.CONTRATANTE), respuesta.roles());
    }

    @Test
    void registrarUnCorreoRepetidoNoDejaCredencialesHuerfanas() {
        registrar();

        assertThrows(DuplicateUserException.class, this::registrar);

        assertEquals(1, credentialRepository.count());
    }

    @Test
    void tresFallosBloqueanLaCuentaAunConLaClaveCorrecta() {
        registrar();

        for (int i = 0; i < 3; i++) {
            assertThrows(InvalidCredentialsException.class,
                    () -> orchestrator.login(new LoginRequest(CORREO, "Incorrecta#123")));
        }

        assertThrows(AccountLockedException.class,
                () -> orchestrator.login(new LoginRequest(CORREO, CLAVE)));
    }

    @Test
    void cambiarLaContrasenaConLaActualFuncionaYAvisa() {
        registrar();
        Long id = orchestrator.login(new LoginRequest(CORREO, CLAVE)).userId();

        orchestrator.changePassword(id, new ChangePasswordRequest(CLAVE, NUEVA));

        assertDoesNotThrow(() -> orchestrator.login(new LoginRequest(CORREO, NUEVA)));
        assertThrows(InvalidCredentialsException.class,
                () -> orchestrator.login(new LoginRequest(CORREO, CLAVE)));
        assertTrue(notifications.sentMessages().stream()
                .anyMatch(m -> m.type().equals("PASSWORD_CHANGED")));
    }

    @Test
    void olvidoYRestablecimientoCompletoYElCodigoSoloSirveUnaVez() {
        registrar();

        orchestrator.forgotPassword(new ForgotPasswordRequest(CORREO));
        String codigo = codigoEnviado();
        orchestrator.resetPassword(new ResetPasswordRequest(CORREO, codigo, NUEVA));

        assertDoesNotThrow(() -> orchestrator.login(new LoginRequest(CORREO, NUEVA)));
        assertThrows(InvalidOtpException.class,
                () -> orchestrator.resetPassword(new ResetPasswordRequest(CORREO, codigo, "Otra#Clave2028x")));
    }

    @Test
    void tresCodigosErroneosInvalidanElCodigoVerdadero() {
        registrar();
        orchestrator.forgotPassword(new ForgotPasswordRequest(CORREO));
        String real = codigoEnviado();
        String erroneo = real.equals("000000") ? "111111" : "000000";

        for (int i = 0; i < 3; i++) {
            assertThrows(InvalidOtpException.class,
                    () -> orchestrator.resetPassword(new ResetPasswordRequest(CORREO, erroneo, NUEVA)));
        }

        assertThrows(InvalidOtpException.class,
                () -> orchestrator.resetPassword(new ResetPasswordRequest(CORREO, real, NUEVA)));
    }
}
