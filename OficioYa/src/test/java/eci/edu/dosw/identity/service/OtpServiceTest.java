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
import java.util.UUID;

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

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID USER_ID_2 = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final UUID OTHER_ID = UUID.fromString("00000000-0000-0000-0000-000000000099");

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
    private Generado generar(UUID userId) {
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
        Generado g = generar(USER_ID);

        assertTrue(g.code().matches("\\d{6}"));
    }

    @Test
    void enLaBaseDeDatosSoloQuedaElHash() {
        Generado g = generar(USER_ID);

        assertNotEquals(g.code(), g.otp().getCodeHash());
        assertEquals(64, g.otp().getCodeHash().length());
    }

    @Test
    void elCodigoEsValidoQuinceMinutos() {
        Otp otp = generar(USER_ID).otp();

        assertEquals(USER_ID, otp.getUserId());
        assertEquals(PURPOSE, otp.getPurpose());
        assertEquals(NOW, otp.getCreatedAt());
        assertEquals(NOW.plusMinutes(15), otp.getExpiresAt());
    }

    @Test
    void alPedirUnoNuevoInvalidaLosAnteriores() {
        generar(USER_ID);

        verify(otpRepository).invalidateActive(USER_ID, PURPOSE);
    }

    @Test
    void cuentaLasSolicitudesDeLaUltimaHora() {
        generar(USER_ID);

        verify(otpRepository).countByUserIdAndPurposeAndCreatedAtAfter(USER_ID, PURPOSE, NOW.minusHours(1));
    }

    @Test
    void permiteLaTerceraSolicitudDeLaHora() {
        when(credentialRepository.existsByUserId(USER_ID)).thenReturn(true);
        when(otpRepository.countByUserIdAndPurposeAndCreatedAtAfter(eq(USER_ID), eq(PURPOSE), any(LocalDateTime.class)))
                .thenReturn(2L);

        assertTrue(service.generate(USER_ID).matches("\\d{6}"));
    }

    @Test
    void rechazaLaCuartaSolicitudDeLaHora() {
        when(credentialRepository.existsByUserId(USER_ID)).thenReturn(true);
        when(otpRepository.countByUserIdAndPurposeAndCreatedAtAfter(eq(USER_ID), eq(PURPOSE), any(LocalDateTime.class)))
                .thenReturn(3L);

        assertThrows(OtpRateLimitException.class, () -> service.generate(USER_ID));

        verify(otpRepository, never()).save(any());
    }

    @Test
    void noGeneraCodigoSiElUsuarioNoTieneCredencial() {
        when(credentialRepository.existsByUserId(OTHER_ID)).thenReturn(false);

        assertThrows(UserNotFoundException.class, () -> service.generate(OTHER_ID));

        verify(otpRepository, never()).save(any());
    }

    // ---------- verifyAndConsume ----------

    @Test
    void unCodigoCorrectoSeConsume() {
        Generado g = generar(USER_ID);

        service.verifyAndConsume(USER_ID, g.code());

        assertTrue(g.otp().isUsed());
    }

    @Test
    void sinCodigoVigenteSeRechaza() {
        when(otpRepository.findActive(eq(USER_ID), eq(PURPOSE), any(LocalDateTime.class)))
                .thenReturn(Optional.empty());

        assertThrows(InvalidOtpException.class, () -> service.verifyAndConsume(USER_ID, "123456"));
    }

    @Test
    void unCodigoIncorrectoSumaUnIntentoYNoSeConsume() {
        Generado g = generar(USER_ID);
        String incorrecto = g.code().equals("000000") ? "111111" : "000000";

        assertThrows(InvalidOtpException.class, () -> service.verifyAndConsume(USER_ID, incorrecto));

        assertEquals(1, g.otp().getAttempts());
        assertFalse(g.otp().isUsed());
    }

    @Test
    void elTercerIntentoFallidoInvalidaElCodigo() {
        Generado g = generar(USER_ID);
        g.otp().setAttempts(2);
        String incorrecto = g.code().equals("000000") ? "111111" : "000000";

        assertThrows(InvalidOtpException.class, () -> service.verifyAndConsume(USER_ID, incorrecto));

        assertTrue(g.otp().isUsed());
    }

    @Test
    void unCodigoNuloCuentaComoIntentoFallido() {
        Generado g = generar(USER_ID);

        assertThrows(InvalidOtpException.class, () -> service.verifyAndConsume(USER_ID, null));

        assertEquals(1, g.otp().getAttempts());
    }

    @Test
    void elCodigoDeUnUsuarioNoSirveParaOtro() {
        Generado g = generar(USER_ID);
        when(otpRepository.findActive(eq(USER_ID_2), eq(PURPOSE), any(LocalDateTime.class)))
                .thenReturn(Optional.of(g.otp()));

        assertThrows(InvalidOtpException.class, () -> service.verifyAndConsume(USER_ID_2, g.code()));

        assertFalse(g.otp().isUsed());
    }
}