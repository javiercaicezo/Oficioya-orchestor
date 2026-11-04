package eci.edu.dosw.identity.service;

import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Prueba unitaria pura: no levanta Spring. */
class JwtProviderTest {

    private static final long TREINTA_MINUTOS_MS = 1_800_000L;

    private static String secreto(String texto32) {
        return Base64.getEncoder().encodeToString(texto32.getBytes(StandardCharsets.UTF_8));
    }

    private static final String SECRETO_A = secreto("0123456789abcdef0123456789abcdef");
    private static final String SECRETO_B = secreto("fedcba9876543210fedcba9876543210");

    private final JwtProvider provider = new JwtProvider(SECRETO_A, TREINTA_MINUTOS_MS);

    @Test
    void generaUnTokenValido() {
        String token = provider.generateToken(7L, List.of("CLIENT"));

        assertTrue(provider.isValid(token));
    }

    @Test
    void elTokenContieneElIdDelUsuario() {
        String token = provider.generateToken(42L, List.of("CLIENT"));

        assertEquals(42L, provider.getUserIdFromToken(token));
    }

    @Test
    void elTokenContieneTodosLosRoles() {
        String token = provider.generateToken(1L, List.of("CLIENT", "WORKER"));

        assertEquals(List.of("CLIENT", "WORKER"), provider.getRolesFromToken(token));
    }

    @Test
    void aceptaUnaListaDeRolesVacia() {
        String token = provider.generateToken(1L, List.of());

        assertTrue(provider.getRolesFromToken(token).isEmpty());
    }

    @Test
    void guardaLaFechaDeEmisionReciente() {
        Instant antes = Instant.now().minusSeconds(2);

        String token = provider.generateToken(1L, List.of("CLIENT"));
        Instant emitido = provider.getIssuedAtFromToken(token);

        assertTrue(emitido.isAfter(antes));
        assertFalse(emitido.isAfter(Instant.now()));
    }

    @Test
    void laExpiracionPorDefectoSonTreintaMinutos() {
        assertEquals(1800, provider.getExpirationSeconds());
    }

    @Test
    void elTokenExpiraDespuesDeLaVigenciaConfigurada() {
        String token = provider.generateToken(1L, List.of("CLIENT"));

        Instant emitido = provider.getIssuedAtFromToken(token);
        Instant expira = provider.parse(token).getExpiration().toInstant();

        assertEquals(1800, expira.getEpochSecond() - emitido.getEpochSecond());
    }

    @Test
    void rechazaUnTokenVencido() {
        JwtProvider caducado = new JwtProvider(SECRETO_A, -1000L);
        String token = caducado.generateToken(1L, List.of("CLIENT"));

        assertFalse(caducado.isValid(token));
        assertThrows(ExpiredJwtException.class, () -> caducado.parse(token));
    }

    @Test
    void rechazaUnTokenFirmadoConOtraClave() {
        JwtProvider ajeno = new JwtProvider(SECRETO_B, TREINTA_MINUTOS_MS);
        String tokenAjeno = ajeno.generateToken(1L, List.of("ADMINISTRATOR"));

        assertFalse(provider.isValid(tokenAjeno));
    }

    @Test
    void rechazaTextoQueNoEsUnToken() {
        assertFalse(provider.isValid("esto-no-es-un-jwt"));
        assertFalse(provider.isValid(""));
        assertFalse(provider.isValid(null));
    }

    @Test
    void rechazaUnaClaveDemasiadoCorta() {
        String corta = secreto("solo16bytes_aqui");

        assertThrows(RuntimeException.class, () -> new JwtProvider(corta, TREINTA_MINUTOS_MS));
    }
}