package eci.edu.dosw.identity.service;

import eci.edu.dosw.identity.exception.InvalidOtpException;
import eci.edu.dosw.identity.exception.OtpRateLimitException;
import eci.edu.dosw.identity.exception.UserNotFoundException;
import eci.edu.dosw.identity.model.Otp;
import eci.edu.dosw.identity.model.OtpPurpose;
import eci.edu.dosw.identity.repository.CredentialRepository;
import eci.edu.dosw.identity.repository.OtpRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Prueba unitaria pura: los repositorios son mocks y el reloj esta fijo. */
class OtpServiceTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 11, 4, 12, 0);
    private static final ZoneId ZONA = ZoneId.systemDefault();
    private static final OtpPurpose PURPOSE = OtpPurpose.RESET_PASSWORD;

    private OtpRepository otpRepository;
    private CredentialRepository credentialRepository;
    private OtpService service;

    private record Generado(String code, Otp otp) {
    }

    @BeforeEach
    void preparar() {
        otpRepository = mock(OtpRepository.class);
        credentialRepository = mock(CredentialRepository.class);
        when(otpRepository.save(any(Otp.class))).thenAnswer(inv -> inv.getArgument(0));
        Clock reloj = Clock.fixed(NOW.atZone(ZONA).toInstant(), ZONA);
        service = new OtpService(otpRepository, credentialRepository, reloj);
    }

    /**
     * Genera un codigo y deja el OTP guardado como "vigente" para que
     * verifyAndConsume lo encuentre.
     */
    private Generado generar(Long userId) {
        when(credentialRepository.existsByUserId(userId)).thenReturn(true);
        String code = service.generate(userId);

        ArgumentCaptor<Otp> captor = ArgumentCaptor.forClass(Otp.class);
        verify(otpRepository).save(captor.capture());
        Otp otp = captor.getValue();

        when(otpRepository.findActive(eq(userId), eq(PURPOSE), any(LocalDateTime.class)))
                .thenReturn(Optional.of(otp));
        return new Generado(code, otp);
    }

    // ---------- generate ----------

    @Test
    void generaUnCodigoDeSeisDigitos() {
        Generado g = generar(1L);

        assertTrue(g.code().matches("\\d{6}"));
    }

    @Test
    void enLaBaseDeDatosSoloQuedaElHash() {
        Generado g = generar(1L);

        assertNotEquals(g.code(), g.otp().getCodeHash());
        assertEquals(64, g.otp().getCodeHash().length());
    }

    @Test
    void elCodigoEsValidoQuinceMinutos() {
        Otp otp = generar(1L).otp();

        assertEquals(1L, otp.getUserId());
        assertEquals(PURPOSE, otp.getPurpose());
        assertEquals(NOW, otp.getCreatedAt());
        assertEquals(NOW.plusMinutes(15), otp.getExpiresAt());
    }

    @Test
    void alPedirUnoNuevoInvalidaLosAnteriores() {
        generar(1L);

        verify(otpRepository).invalidateActive(1L, PURPOSE);
    }

    @Test
    void cuentaLasSolicitudesDeLaUltimaHora() {
        generar(1L);

        verify(otpRepository).countByUserIdAndPurposeAndCreatedAtAfter(1L, PURPOSE, NOW.minusHours(1));
    }

    @Test
    void permiteLaTerceraSolicitudDeLaHora() {
        when(credentialRepository.existsByUserId(1L)).thenReturn(true);
        when(otpRepository.countByUserIdAndPurposeAndCreatedAtAfter(eq(1L), eq(PURPOSE), any(LocalDateTime.class)))
                .thenReturn(2L);

        assertTrue(service.generate(1L).matches("\\d{6}"));
    }

    @Test
    void rechazaLaCuartaSolicitudDeLaHora() {
        when(credentialRepository.existsByUserId(1L)).thenReturn(true);
        when(otpRepository.countByUserIdAndPurposeAndCreatedAtAfter(eq(1L), eq(PURPOSE), any(LocalDateTime.class)))
                .thenReturn(3L);

        assertThrows(OtpRateLimitException.class, () -> service.generate(1L));

        verify(otpRepository, never()).save(any());
    }

    @Test
    void noGeneraCodigoSiElUsuarioNoTieneCredencial() {
        when(credentialRepository.existsByUserId(99L)).thenReturn(false);

        assertThrows(UserNotFoundException.class, () -> service.generate(99L));

        verify(otpRepository, never()).save(any());
    }

    // ---------- verifyAndConsume ----------

    @Test
    void unCodigoCorrectoSeConsume() {
        Generado g = generar(1L);

        service.verifyAndConsume(1L, g.code());

        assertTrue(g.otp().isUsed());
    }

    @Test
    void sinCodigoVigenteSeRechaza() {
        when(otpRepository.findActive(eq(1L), eq(PURPOSE), any(LocalDateTime.class)))
                .thenReturn(Optional.empty());

        assertThrows(InvalidOtpException.class, () -> service.verifyAndConsume(1L, "123456"));
    }

    @Test
    void unCodigoIncorrectoSumaUnIntentoYNoSeConsume() {
        Generado g = generar(1L);
        String incorrecto = g.code().equals("000000") ? "111111" : "000000";

        assertThrows(InvalidOtpException.class, () -> service.verifyAndConsume(1L, incorrecto));

        assertEquals(1, g.otp().getAttempts());
        assertFalse(g.otp().isUsed());
    }

    @Test
    void elTercerIntentoFallidoInvalidaElCodigo() {
        Generado g = generar(1L);
        g.otp().setAttempts(2);
        String incorrecto = g.code().equals("000000") ? "111111" : "000000";

        assertThrows(InvalidOtpException.class, () -> service.verifyAndConsume(1L, incorrecto));

        assertTrue(g.otp().isUsed());
    }

    @Test
    void unCodigoNuloCuentaComoIntentoFallido() {
        Generado g = generar(1L);

        assertThrows(InvalidOtpException.class, () -> service.verifyAndConsume(1L, null));

        assertEquals(1, g.otp().getAttempts());
    }

    @Test
    void elCodigoDeUnUsuarioNoSirveParaOtro() {
        Generado g = generar(1L);
        when(otpRepository.findActive(eq(2L), eq(PURPOSE), any(LocalDateTime.class)))
                .thenReturn(Optional.of(g.otp()));

        assertThrows(InvalidOtpException.class, () -> service.verifyAndConsume(2L, g.code()));

        assertFalse(g.otp().isUsed());
    }
}