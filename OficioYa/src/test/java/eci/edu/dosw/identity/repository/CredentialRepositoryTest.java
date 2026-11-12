package eci.edu.dosw.identity.repository;

import eci.edu.dosw.identity.model.Credential;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Prueba la tabla credential con la migracion real de Flyway sobre H2 (modo PostgreSQL). */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class CredentialRepositoryTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 10, 28, 12, 0);

    @Autowired
    private CredentialRepository credentialRepository;

    @Test
    void guardaYBuscaPorUserId() {
        UUID u1 = UUID.randomUUID();
        credentialRepository.save(new Credential(u1, "hash-1", NOW));

        Credential encontrada = credentialRepository.findByUserId(u1).orElseThrow();

        assertNotNull(encontrada.getId());
        assertEquals(u1, encontrada.getUserId());
        assertEquals("hash-1", encontrada.getPasswordHash());
        assertEquals(NOW, encontrada.getPasswordChangedAt());
    }

    @Test
    void usaValoresPorDefectoParaIntentosYBloqueo() {
        UUID u2 = UUID.randomUUID();
        Credential guardada = credentialRepository.saveAndFlush(new Credential(u2, "hash-2", NOW));

        assertEquals(0, guardada.getFailedAttempts());
        assertNull(guardada.getLockedUntil());
        assertNull(guardada.getLastLogin());
    }

    @Test
    void userIdDebeSerUnico() {
        UUID u3 = UUID.randomUUID();
        credentialRepository.saveAndFlush(new Credential(u3, "hash-a", NOW));

        assertThrows(DataIntegrityViolationException.class,
                () -> credentialRepository.saveAndFlush(new Credential(u3, "hash-b", NOW)));
    }

    @Test
    void existsByUserIdIndicaSiHayCredencial() {
        UUID u4 = UUID.randomUUID();
        credentialRepository.save(new Credential(u4, "hash-4", NOW));

        assertTrue(credentialRepository.existsByUserId(u4));
        assertFalse(credentialRepository.existsByUserId(UUID.randomUUID()));
    }

    @Test
    void deleteByUserIdBorraLaCredencial() {
        UUID u5 = UUID.randomUUID();
        credentialRepository.save(new Credential(u5, "hash-5", NOW));

        long borradas = credentialRepository.deleteByUserId(u5);

        assertEquals(1, borradas);
        assertFalse(credentialRepository.existsByUserId(u5));
    }

    @Test
    void actualizaIntentosFallidosYBloqueo() {
        UUID u6 = UUID.randomUUID();
        Credential credencial = credentialRepository.save(new Credential(u6, "hash-6", NOW));
        credencial.setFailedAttempts(3);
        credencial.setLockedUntil(NOW.plusMinutes(15));
        credentialRepository.saveAndFlush(credencial);

        Credential recargada = credentialRepository.findByUserId(u6).orElseThrow();

        assertEquals(3, recargada.getFailedAttempts());
        assertEquals(NOW.plusMinutes(15), recargada.getLockedUntil());
    }
}
