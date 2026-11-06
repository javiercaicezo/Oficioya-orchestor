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

    private Credential credencial(Long userId) {
        Credential c = new Credential(userId, HASH, NOW.minusDays(1));
        when(repository.findByUserId(userId)).thenReturn(Optional.of(c));
        return c;
    }

    // ---------- create ----------

    @Test
    void createGuardaLaContrasenaCifrada() {
        when(repository.existsByUserId(1L)).thenReturn(false);

        service.create(1L, VALIDA);

        ArgumentCaptor<Credential> captor = ArgumentCaptor.forClass(Credential.class);
        verify(repository).save(captor.capture());
        Credential guardada = captor.getValue();
        assertEquals(1L, guardada.getUserId());
        assertNotEquals(VALIDA, guardada.getPasswordHash());
        assertTrue(ENCODER.matches(VALIDA, guardada.getPasswordHash()));
        assertEquals(NOW, guardada.getPasswordChangedAt());
    }

    @Test
    void createRechazaUnaContrasenaDebil() {
        assertThrows(WeakPasswordException.class, () -> service.create(1L, "debil"));

        verify(repository, never()).save(any());
    }

    @Test
    void createRechazaUnUsuarioQueYaTieneCredencial() {
        when(repository.existsByUserId(1L)).thenReturn(true);

        assertThrows(DuplicateUserException.class, () -> service.create(1L, VALIDA));

        verify(repository, never()).save(any());
    }

    // ---------- authenticate ----------

    @Test
    void authenticateExitosoReiniciaIntentosYRegistraElLogin() {
        Credential c = credencial(1L);
        c.setFailedAttempts(3);

        Credential resultado = service.authenticate(1L, VALIDA);

        assertEquals(0, resultado.getFailedAttempts());
        assertNull(resultado.getLockedUntil());
        assertEquals(NOW, resultado.getLastLogin());
    }

    @Test
    void usuarioInexistenteYContrasenaIncorrectaDanElMismoMensaje() {
        when(repository.findByUserId(99L)).thenReturn(Optional.empty());
        credencial(1L);

        String sinUsuario = assertThrows(InvalidCredentialsException.class,
                () -> service.authenticate(99L, VALIDA)).getMessage();
        String malaClave = assertThrows(InvalidCredentialsException.class,
                () -> service.authenticate(1L, "Incorrecta#2026x")).getMessage();

        assertEquals(sinUsuario, malaClave);
    }

    @Test
    void unaContrasenaIncorrectaSumaUnIntento() {
        Credential c = credencial(1L);

        assertThrows(InvalidCredentialsException.class, () -> service.authenticate(1L, "Incorrecta#2026x"));

        assertEquals(1, c.getFailedAttempts());
        assertNull(c.getLockedUntil());
        verify(repository).save(c);
    }

    @Test
    void laContrasenaNulaCuentaComoIntentoFallido() {
        Credential c = credencial(1L);

        assertThrows(InvalidCredentialsException.class, () -> service.authenticate(1L, null));

        assertEquals(1, c.getFailedAttempts());
    }

    @Test
    void elQuintoIntentoFallidoBloqueaLaCuentaQuinceMinutos() {
        Credential c = credencial(1L);
        c.setFailedAttempts(4);

        assertThrows(InvalidCredentialsException.class, () -> service.authenticate(1L, "Incorrecta#2026x"));

        assertEquals(NOW.plusMinutes(15), c.getLockedUntil());
        assertEquals(0, c.getFailedAttempts());
    }

    @Test
    void unaCuentaBloqueadaSeRechazaAunConLaContrasenaCorrecta() {
        Credential c = credencial(1L);
        c.setLockedUntil(NOW.plusMinutes(5));

        assertThrows(AccountLockedException.class, () -> service.authenticate(1L, VALIDA));

        verify(repository, never()).save(any());
    }

    @Test
    void cuandoElBloqueoVenceSePuedeIniciarSesion() {
        Credential c = credencial(1L);
        c.setLockedUntil(NOW.minusMinutes(1));

        Credential resultado = service.authenticate(1L, VALIDA);

        assertNull(resultado.getLockedUntil());
        assertEquals(NOW, resultado.getLastLogin());
    }

    // ---------- changePassword ----------

    @Test
    void changePasswordGuardaLaNuevaContrasenaCifrada() {
        Credential c = credencial(1L);
        c.setFailedAttempts(2);

        service.changePassword(1L, VALIDA, NUEVA);

        assertTrue(ENCODER.matches(NUEVA, c.getPasswordHash()));
        assertFalse(ENCODER.matches(VALIDA, c.getPasswordHash()));
        assertEquals(NOW, c.getPasswordChangedAt());
        assertEquals(0, c.getFailedAttempts());
    }

    @Test
    void changePasswordRechazaSiLaActualEsIncorrecta() {
        Credential c = credencial(1L);

        assertThrows(InvalidCredentialsException.class,
                () -> service.changePassword(1L, "Incorrecta#2026x", NUEVA));

        assertEquals(HASH, c.getPasswordHash());
    }

    @Test
    void changePasswordRechazaUnaNuevaIgualALaActual() {
        credencial(1L);

        WeakPasswordException e = assertThrows(WeakPasswordException.class,
                () -> service.changePassword(1L, VALIDA, VALIDA));

        assertTrue(e.getMessage().contains("diferente"));
    }

    @Test
    void changePasswordRechazaUnaNuevaDebil() {
        credencial(1L);

        assertThrows(WeakPasswordException.class, () -> service.changePassword(1L, VALIDA, "debil"));
    }

    @Test
    void changePasswordRechazaUnaCuentaBloqueada() {
        Credential c = credencial(1L);
        c.setLockedUntil(NOW.plusMinutes(10));

        assertThrows(AccountLockedException.class, () -> service.changePassword(1L, VALIDA, NUEVA));
    }

    // ---------- resetPassword ----------

    @Test
    void resetPasswordCambiaLaContrasenaYDesbloqueaLaCuenta() {
        Credential c = credencial(1L);
        c.setFailedAttempts(3);
        c.setLockedUntil(NOW.plusMinutes(10));

        service.resetPassword(1L, NUEVA);

        assertTrue(ENCODER.matches(NUEVA, c.getPasswordHash()));
        assertNull(c.getLockedUntil());
        assertEquals(0, c.getFailedAttempts());
        assertEquals(NOW, c.getPasswordChangedAt());
    }

    @Test
    void resetPasswordFallaSiElUsuarioNoExiste() {
        when(repository.findByUserId(99L)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> service.resetPassword(99L, NUEVA));
    }

    @Test
    void resetPasswordRechazaUnaNuevaIgualALaActual() {
        credencial(1L);

        assertThrows(WeakPasswordException.class, () -> service.resetPassword(1L, VALIDA));
    }

    // ---------- validateNewPassword ----------

    @Test
    void validateNewPasswordAceptaUnaContrasenaValidaYNoCambiaNada() {
        Credential c = credencial(1L);

        service.validateNewPassword(1L, NUEVA);

        assertEquals(HASH, c.getPasswordHash());
        verify(repository, never()).save(any(Credential.class));
    }

    @Test
    void validateNewPasswordRechazaUnaContrasenaDebil() {
        credencial(1L);

        assertThrows(WeakPasswordException.class, () -> service.validateNewPassword(1L, "debil"));
    }

    @Test
    void validateNewPasswordRechazaUnaIgualALaActual() {
        credencial(1L);

        assertThrows(WeakPasswordException.class, () -> service.validateNewPassword(1L, VALIDA));
    }

    @Test
    void validateNewPasswordRechazaUnUsuarioSinCredencial() {
        when(repository.findByUserId(99L)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> service.validateNewPassword(99L, NUEVA));
    }

    // ---------- delete / exists ----------

    @Test
    void deleteBorraLaCredencialDelUsuario() {
        service.delete(5L);

        verify(repository).deleteByUserId(5L);
    }

    @Test
    void existsConsultaAlRepositorio() {
        when(repository.existsByUserId(1L)).thenReturn(true);
        when(repository.existsByUserId(2L)).thenReturn(false);

        assertTrue(service.exists(1L));
        assertFalse(service.exists(2L));
    }

    // ---------- wasIssuedBeforePasswordChange ----------

    private static Instant enZona(LocalDateTime t) {
        return t.atZone(ZONA).toInstant();
    }

    @Test
    void unTokenAnteriorAlCambioDeContrasenaQuedaInvalidado() {
        credencial(1L).setPasswordChangedAt(NOW);
        assertTrue(service.wasIssuedBeforePasswordChange(1L, enZona(NOW).minusSeconds(1)));
    }

    @Test
    void unTokenDelMismoSegundoDelCambioSigueSiendoValido() {
        credencial(1L).setPasswordChangedAt(NOW.plusNanos(700_000_000));
        assertFalse(service.wasIssuedBeforePasswordChange(1L, enZona(NOW)));
    }

    @Test
    void unTokenPosteriorAlCambioEsValido() {
        credencial(1L).setPasswordChangedAt(NOW);
        assertFalse(service.wasIssuedBeforePasswordChange(1L, enZona(NOW).plusSeconds(5)));
    }

    @Test
    void sinCredencialElTokenQuedaInvalidado() {
        when(repository.findByUserId(9L)).thenReturn(Optional.empty());
        assertTrue(service.wasIssuedBeforePasswordChange(9L, enZona(NOW)));
    }

    @Test
    void sinFechaDeCambioElTokenEsValido() {
        credencial(1L).setPasswordChangedAt(null);
        assertFalse(service.wasIssuedBeforePasswordChange(1L, enZona(NOW)));
    }

    @Test
    void laComparacionUsaLaZonaDelReloj() {
        ZoneId bogota = ZoneId.of("America/Bogota");
        CredentialService enBogota = new CredentialService(repository, ENCODER,
                new PasswordPolicyService(ENCODER), Clock.fixed(Instant.now(), bogota));
        Credential c = new Credential(2L, HASH, NOW);
        when(repository.findByUserId(2L)).thenReturn(Optional.of(c));

        assertFalse(enBogota.wasIssuedBeforePasswordChange(2L, NOW.atZone(bogota).toInstant()));
        assertTrue(enBogota.wasIssuedBeforePasswordChange(2L, NOW.toInstant(ZoneOffset.UTC)));
    }
}