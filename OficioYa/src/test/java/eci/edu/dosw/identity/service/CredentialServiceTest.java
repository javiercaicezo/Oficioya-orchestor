package eci.edu.dosw.identity.service;

import eci.edu.dosw.identity.exception.AccountLockedException;
import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.identity.exception.InvalidCredentialsException;
import eci.edu.dosw.identity.exception.UserNotFoundException;
import eci.edu.dosw.identity.exception.WeakPasswordException;
import eci.edu.dosw.identity.model.Credential;
import eci.edu.dosw.identity.repository.CredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Prueba unitaria pura: el repositorio es un mock y el reloj esta fijo. */
class CredentialServiceTest {

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID USER_ID_2 = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final UUID OTHER_ID = UUID.fromString("00000000-0000-0000-0000-000000000099");

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 11, 4, 12, 0);
    private static final ZoneId ZONA = ZoneId.systemDefault();
    private static final String VALIDA = "Segura#Clave2026";
    private static final String NUEVA = "Otra#Clave2027x";

    private static final PasswordEncoder ENCODER = new BCryptPasswordEncoder();
    private static final String HASH = ENCODER.encode(VALIDA);

    private CredentialRepository repository;
    private CredentialService service;

    @BeforeEach
    void preparar() {
        repository = mock(CredentialRepository.class);
        when(repository.save(any(Credential.class))).thenAnswer(inv -> inv.getArgument(0));
        Clock reloj = Clock.fixed(NOW.atZone(ZONA).toInstant(), ZONA);
        service = new CredentialService(repository, ENCODER, new PasswordPolicyService(ENCODER), reloj);
    }

    private Credential credencial(UUID userId) {
        Credential c = new Credential(userId, HASH, NOW.minusDays(1));
        when(repository.findByUserId(userId)).thenReturn(Optional.of(c));
        return c;
    }

    // ---------- create ----------

    @Test
    void createGuardaLaContrasenaCifrada() {
        when(repository.existsByUserId(USER_ID)).thenReturn(false);

        service.create(USER_ID, VALIDA);

        ArgumentCaptor<Credential> captor = ArgumentCaptor.forClass(Credential.class);
        verify(repository).save(captor.capture());
        Credential guardada = captor.getValue();
        assertEquals(USER_ID, guardada.getUserId());
        assertNotEquals(VALIDA, guardada.getPasswordHash());
        assertTrue(ENCODER.matches(VALIDA, guardada.getPasswordHash()));
        assertEquals(NOW, guardada.getPasswordChangedAt());
    }

    @Test
    void createRechazaUnaContrasenaDebil() {
        assertThrows(WeakPasswordException.class, () -> service.create(USER_ID, "debil"));

        verify(repository, never()).save(any());
    }

    @Test
    void createRechazaUnUsuarioQueYaTieneCredencial() {
        when(repository.existsByUserId(USER_ID)).thenReturn(true);

        assertThrows(DuplicateUserException.class, () -> service.create(USER_ID, VALIDA));

        verify(repository, never()).save(any());
    }

    // ---------- authenticate ----------

    @Test
    void authenticateExitosoReiniciaIntentosYRegistraElLogin() {
        Credential c = credencial(USER_ID);
        c.setFailedAttempts(2);

        Credential resultado = service.authenticate(USER_ID, VALIDA);

        assertEquals(0, resultado.getFailedAttempts());
        assertNull(resultado.getLockedUntil());
        assertEquals(NOW, resultado.getLastLogin());
    }

    @Test
    void usuarioInexistenteYContrasenaIncorrectaDanElMismoMensaje() {
        when(repository.findByUserId(OTHER_ID)).thenReturn(Optional.empty());
        credencial(USER_ID);

        String sinUsuario = assertThrows(InvalidCredentialsException.class,
                () -> service.authenticate(OTHER_ID, VALIDA)).getMessage();
        String malaClave = assertThrows(InvalidCredentialsException.class,
                () -> service.authenticate(USER_ID, "Incorrecta#2026x")).getMessage();

        assertEquals(sinUsuario, malaClave);
    }

    @Test
    void unaContrasenaIncorrectaSumaUnIntento() {
        Credential c = credencial(USER_ID);

        assertThrows(InvalidCredentialsException.class, () -> service.authenticate(USER_ID, "Incorrecta#2026x"));

        assertEquals(1, c.getFailedAttempts());
        assertNull(c.getLockedUntil());
        verify(repository).save(c);
    }

    @Test
    void laContrasenaNulaCuentaComoIntentoFallido() {
        Credential c = credencial(USER_ID);

        assertThrows(InvalidCredentialsException.class, () -> service.authenticate(USER_ID, null));

        assertEquals(1, c.getFailedAttempts());
    }

    @Test
    void elTercerIntentoFallidoBloqueaLaCuentaQuinceMinutos() {
        Credential c = credencial(USER_ID);
        c.setFailedAttempts(2);

        assertThrows(InvalidCredentialsException.class, () -> service.authenticate(USER_ID, "Incorrecta#2026x"));

        assertEquals(NOW.plusMinutes(15), c.getLockedUntil());
        assertEquals(0, c.getFailedAttempts());
    }

    @Test
    void unaCuentaBloqueadaSeRechazaAunConLaContrasenaCorrecta() {
        Credential c = credencial(USER_ID);
        c.setLockedUntil(NOW.plusMinutes(5));

        assertThrows(AccountLockedException.class, () -> service.authenticate(USER_ID, VALIDA));

        verify(repository, never()).save(any());
    }

    @Test
    void cuandoElBloqueoVenceSePuedeIniciarSesion() {
        Credential c = credencial(USER_ID);
        c.setLockedUntil(NOW.minusMinutes(1));

        Credential resultado = service.authenticate(USER_ID, VALIDA);

        assertNull(resultado.getLockedUntil());
        assertEquals(NOW, resultado.getLastLogin());
    }

    // ---------- changePassword ----------

    @Test
    void changePasswordGuardaLaNuevaContrasenaCifrada() {
        Credential c = credencial(USER_ID);
        c.setFailedAttempts(2);

        service.changePassword(USER_ID, VALIDA, NUEVA);

        assertTrue(ENCODER.matches(NUEVA, c.getPasswordHash()));
        assertFalse(ENCODER.matches(VALIDA, c.getPasswordHash()));
        assertEquals(NOW, c.getPasswordChangedAt());
        assertEquals(0, c.getFailedAttempts());
    }

    @Test
    void changePasswordRechazaSiLaActualEsIncorrecta() {
        Credential c = credencial(USER_ID);

        assertThrows(InvalidCredentialsException.class,
                () -> service.changePassword(USER_ID, "Incorrecta#2026x", NUEVA));

        assertEquals(HASH, c.getPasswordHash());
    }

    @Test
    void changePasswordRechazaUnaNuevaIgualALaActual() {
        credencial(USER_ID);

        WeakPasswordException e = assertThrows(WeakPasswordException.class,
                () -> service.changePassword(USER_ID, VALIDA, VALIDA));

        assertTrue(e.getMessage().contains("diferente"));
    }

    @Test
    void changePasswordRechazaUnaNuevaDebil() {
        credencial(USER_ID);

        assertThrows(WeakPasswordException.class, () -> service.changePassword(USER_ID, VALIDA, "debil"));
    }

    @Test
    void changePasswordRechazaUnaCuentaBloqueada() {
        Credential c = credencial(USER_ID);
        c.setLockedUntil(NOW.plusMinutes(10));

        assertThrows(AccountLockedException.class, () -> service.changePassword(USER_ID, VALIDA, NUEVA));
    }

    // ---------- resetPassword ----------

    @Test
    void resetPasswordCambiaLaContrasenaYDesbloqueaLaCuenta() {
        Credential c = credencial(USER_ID);
        c.setFailedAttempts(2);
        c.setLockedUntil(NOW.plusMinutes(10));

        service.resetPassword(USER_ID, NUEVA);

        assertTrue(ENCODER.matches(NUEVA, c.getPasswordHash()));
        assertNull(c.getLockedUntil());
        assertEquals(0, c.getFailedAttempts());
        assertEquals(NOW, c.getPasswordChangedAt());
    }

    @Test
    void resetPasswordFallaSiElUsuarioNoExiste() {
        when(repository.findByUserId(OTHER_ID)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> service.resetPassword(OTHER_ID, NUEVA));
    }

    @Test
    void resetPasswordRechazaUnaNuevaIgualALaActual() {
        credencial(USER_ID);

        assertThrows(WeakPasswordException.class, () -> service.resetPassword(USER_ID, VALIDA));
    }

    // ---------- validateNewPassword ----------

    @Test
    void validateNewPasswordAceptaUnaContrasenaValidaYNoCambiaNada() {
        Credential c = credencial(USER_ID);

        service.validateNewPassword(USER_ID, NUEVA);

        assertEquals(HASH, c.getPasswordHash());
        verify(repository, never()).save(any(Credential.class));
    }

    @Test
    void validateNewPasswordRechazaUnaContrasenaDebil() {
        credencial(USER_ID);

        assertThrows(WeakPasswordException.class, () -> service.validateNewPassword(USER_ID, "debil"));
    }

    @Test
    void validateNewPasswordRechazaUnaIgualALaActual() {
        credencial(USER_ID);

        assertThrows(WeakPasswordException.class, () -> service.validateNewPassword(USER_ID, VALIDA));
    }

    @Test
    void validateNewPasswordRechazaUnUsuarioSinCredencial() {
        when(repository.findByUserId(OTHER_ID)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> service.validateNewPassword(OTHER_ID, NUEVA));
    }

    // ---------- delete / exists ----------

    @Test
    void deleteBorraLaCredencialDelUsuario() {
        service.delete(USER_ID);

        verify(repository).deleteByUserId(USER_ID);
    }

    @Test
    void existsConsultaAlRepositorio() {
        when(repository.existsByUserId(USER_ID)).thenReturn(true);
        when(repository.existsByUserId(USER_ID_2)).thenReturn(false);

        assertTrue(service.exists(USER_ID));
        assertFalse(service.exists(USER_ID_2));
    }

    // ---------- wasIssuedBeforePasswordChange ----------

    private static Instant enZona(LocalDateTime t) {
        return t.atZone(ZONA).toInstant();
    }

    @Test
    void unTokenAnteriorAlCambioDeContrasenaQuedaInvalidado() {
        credencial(USER_ID).setPasswordChangedAt(NOW);
        assertTrue(service.wasIssuedBeforePasswordChange(USER_ID, enZona(NOW).minusSeconds(1)));
    }

    @Test
    void unTokenDelMismoSegundoDelCambioSigueSiendoValido() {
        credencial(USER_ID).setPasswordChangedAt(NOW.plusNanos(700_000_000));
        assertFalse(service.wasIssuedBeforePasswordChange(USER_ID, enZona(NOW)));
    }

    @Test
    void unTokenPosteriorAlCambioEsValido() {
        credencial(USER_ID).setPasswordChangedAt(NOW);
        assertFalse(service.wasIssuedBeforePasswordChange(USER_ID, enZona(NOW).plusSeconds(5)));
    }

    @Test
    void sinCredencialElTokenQuedaInvalidado() {
        when(repository.findByUserId(OTHER_ID)).thenReturn(Optional.empty());
        assertTrue(service.wasIssuedBeforePasswordChange(OTHER_ID, enZona(NOW)));
    }

    @Test
    void sinFechaDeCambioElTokenEsValido() {
        credencial(USER_ID).setPasswordChangedAt(null);
        assertFalse(service.wasIssuedBeforePasswordChange(USER_ID, enZona(NOW)));
    }

    @Test
    void laComparacionUsaLaZonaDelReloj() {
        ZoneId bogota = ZoneId.of("America/Bogota");
        CredentialService enBogota = new CredentialService(repository, ENCODER,
                new PasswordPolicyService(ENCODER), Clock.fixed(Instant.now(), bogota));
        Credential c = new Credential(USER_ID_2, HASH, NOW);
        when(repository.findByUserId(USER_ID_2)).thenReturn(Optional.of(c));

        assertFalse(enBogota.wasIssuedBeforePasswordChange(USER_ID_2, NOW.atZone(bogota).toInstant()));
        assertTrue(enBogota.wasIssuedBeforePasswordChange(USER_ID_2, NOW.toInstant(ZoneOffset.UTC)));
    }
}