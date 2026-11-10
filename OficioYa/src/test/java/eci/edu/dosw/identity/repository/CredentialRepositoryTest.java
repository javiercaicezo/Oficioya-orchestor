package eci.edu.dosw.identity.repository;

import eci.edu.dosw.identity.model.Credential;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

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
        credentialRepository.save(new Credential(1L, "hash-1", NOW));

        Credential encontrada = credentialRepository.findByUserId(1L).orElseThrow();

        assertNotNull(encontrada.getId());
        assertEquals(1L, encontrada.getUserId());
        assertEquals("hash-1", encontrada.getPasswordHash());
        assertEquals(NOW, encontrada.getPasswordChangedAt());
    }

    @Test
    void usaValoresPorDefectoParaIntentosYBloqueo() {
        Credential guardada = credentialRepository.saveAndFlush(new Credential(2L, "hash-2", NOW));

        assertEquals(0, guardada.getFailedAttempts());
        assertNull(guardada.getLockedUntil());
        assertNull(guardada.getLastLogin());
    }

    @Test
    void userIdDebeSerUnico() {
        credentialRepository.saveAndFlush(new Credential(3L, "hash-a", NOW));

        assertThrows(DataIntegrityViolationException.class,
                () -> credentialRepository.saveAndFlush(new Credential(3L, "hash-b", NOW)));
    }

    @Test
    void existsByUserIdIndicaSiHayCredencial() {
        credentialRepository.save(new Credential(4L, "hash-4", NOW));

        assertTrue(credentialRepository.existsByUserId(4L));
        assertFalse(credentialRepository.existsByUserId(404L));
    }

    @Test
    void deleteByUserIdBorraLaCredencial() {
        credentialRepository.save(new Credential(5L, "hash-5", NOW));

        long borradas = credentialRepository.deleteByUserId(5L);

        assertEquals(1, borradas);
        assertFalse(credentialRepository.existsByUserId(5L));
    }

    @Test
    void actualizaIntentosFallidosYBloqueo() {
        Credential credencial = credentialRepository.save(new Credential(6L, "hash-6", NOW));
        credencial.setFailedAttempts(3);
        credencial.setLockedUntil(NOW.plusMinutes(15));
        credentialRepository.saveAndFlush(credencial);

        Credential recargada = credentialRepository.findByUserId(6L).orElseThrow();

        assertEquals(3, recargada.getFailedAttempts());
        assertEquals(NOW.plusMinutes(15), recargada.getLockedUntil());
    }
}
