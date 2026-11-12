package eci.edu.dosw.identity.repository;

import eci.edu.dosw.identity.model.Credential;
import eci.edu.dosw.identity.model.Otp;
import eci.edu.dosw.identity.model.OtpPurpose;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Prueba la tabla otp con la migracion real de Flyway sobre H2 (modo PostgreSQL). */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class OtpRepositoryTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 10, 28, 12, 0);
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private OtpRepository otpRepository;

    @BeforeEach
    void crearCredencial() {
        credentialRepository.saveAndFlush(new Credential(USER_ID, "hash", NOW));
    }

    private Otp otp(String hash, LocalDateTime creado, LocalDateTime vence) {
        return new Otp(USER_ID, hash, OtpPurpose.RESET_PASSWORD, creado, vence);
    }

    @Test
    void findActiveDevuelveElOtpVigenteMasReciente() {
        otpRepository.save(otp("viejo", NOW.minusMinutes(10), NOW.plusMinutes(5)));
        otpRepository.save(otp("nuevo", NOW.minusMinutes(2), NOW.plusMinutes(13)));

        Otp activo = otpRepository.findActive(USER_ID, OtpPurpose.RESET_PASSWORD, NOW).orElseThrow();

        assertEquals("nuevo", activo.getCodeHash());
    }

    @Test
    void findActiveIgnoraOtpUsadosYVencidos() {
        Otp usado = otp("usado", NOW.minusMinutes(5), NOW.plusMinutes(10));
        usado.setUsed(true);
        otpRepository.save(usado);
        otpRepository.save(otp("vencido", NOW.minusMinutes(30), NOW.minusMinutes(1)));

        assertTrue(otpRepository.findActive(USER_ID, OtpPurpose.RESET_PASSWORD, NOW).isEmpty());
    }

    @Test
    void cuentaLosOtpCreadosDespuesDeUnaFecha() {
        otpRepository.save(otp("a", NOW.minusMinutes(10), NOW.plusMinutes(5)));
        otpRepository.save(otp("b", NOW.minusMinutes(50), NOW.minusMinutes(35)));
        otpRepository.save(otp("c", NOW.minusMinutes(90), NOW.minusMinutes(75)));

        long ultimaHora = otpRepository.countByUserIdAndPurposeAndCreatedAtAfter(
                USER_ID, OtpPurpose.RESET_PASSWORD, NOW.minusHours(1));

        assertEquals(2, ultimaHora);
    }

    @Test
    void invalidateActiveMarcaComoUsadosLosOtpVigentes() {
        otpRepository.save(otp("a", NOW.minusMinutes(3), NOW.plusMinutes(12)));
        otpRepository.save(otp("b", NOW.minusMinutes(1), NOW.plusMinutes(14)));

        int invalidados = otpRepository.invalidateActive(USER_ID, OtpPurpose.RESET_PASSWORD);

        assertEquals(2, invalidados);
        assertTrue(otpRepository.findActive(USER_ID, OtpPurpose.RESET_PASSWORD, NOW).isEmpty());
    }

    @Test
    void guardaIntentosYBanderaDeUso() {
        Otp guardado = otpRepository.saveAndFlush(otp("x", NOW, NOW.plusMinutes(15)));

        assertEquals(0, guardado.getAttempts());
        assertEquals(false, guardado.isUsed());
    }

    @Test
    void noPermiteOtpSinCredencial() {
        Otp huerfano = new Otp(UUID.randomUUID(), "hash", OtpPurpose.RESET_PASSWORD, NOW, NOW.plusMinutes(15));

        assertThrows(DataIntegrityViolationException.class, () -> otpRepository.saveAndFlush(huerfano));
    }
}
