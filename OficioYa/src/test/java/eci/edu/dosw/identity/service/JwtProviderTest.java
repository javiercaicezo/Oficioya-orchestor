package eci.edu.dosw.identity.service;

import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Prueba unitaria pura: no levanta Spring. */
class JwtProviderTest {

    private static final long QUINCE_MINUTOS_MS = 900_000L;

    private static String secreto(String texto32) {
        return Base64.getEncoder().encodeToString(texto32.getBytes(StandardCharsets.UTF_8));
    }

    private static final String SECRETO_A = secreto("0123456789abcdef0123456789abcdef");
    private static final String SECRETO_B = secreto("fedcba9876543210fedcba9876543210");

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID USER_ID_42 = UUID.fromString("00000000-0000-0000-0000-000000000042");

    private final JwtProvider provider = new JwtProvider(SECRETO_A, QUINCE_MINUTOS_MS);

    @Test
    void generaUnTokenValido() {
        String token = provider.generateToken(USER_ID, List.of("CONTRATANTE"));

        assertTrue(provider.isValid(token));
    }

    @Test
    void elTokenContieneElIdDelUsuario() {
        String token = provider.generateToken(USER_ID_42, List.of("CONTRATANTE"));

        assertEquals(USER_ID_42, provider.getUserIdFromToken(token));
    }

    @Test
    void elTokenContieneTodosLosRoles() {
        String token = provider.generateToken(USER_ID, List.of("CONTRATANTE", "TRABAJADOR"));

        assertEquals(List.of("CONTRATANTE", "TRABAJADOR"), provider.getRolesFromToken(token));
    }

    @Test
    void elTokenFiltraElRolServiceEnTokensDeUsuario() {
        String token = provider.generateToken(USER_ID, List.of("CONTRATANTE", "SERVICE"));

        assertEquals(List.of("CONTRATANTE"), provider.getRolesFromToken(token));
    }

    @Test
    void generaTokenDeServicio() {
        String token = provider.generateServiceToken();

        assertTrue(provider.isValid(token));
        assertEquals(List.of("SERVICE"), provider.getRolesFromToken(token));
        assertEquals(JwtProvider.SERVICE_SUBJECT, provider.parse(token).getSubject());
        assertDoesNotThrow(() -> UUID.fromString(provider.parse(token).getSubject()));
    }

    @Test
    void aceptaUnaListaDeRolesVacia() {
        String token = provider.generateToken(USER_ID, List.of());

        assertTrue(provider.getRolesFromToken(token).isEmpty());
    }

    @Test
    void guardaLaFechaDeEmisionReciente() {
        Instant antes = Instant.now().minusSeconds(2);

        String token = provider.generateToken(USER_ID, List.of("CONTRATANTE"));
        Instant emitido = provider.getIssuedAtFromToken(token);

        assertTrue(emitido.isAfter(antes));
        assertFalse(emitido.isAfter(Instant.now()));
    }

    @Test
    void laExpiracionPorDefectoSonQuinceMinutos() {
        assertEquals(900, provider.getExpirationSeconds());
    }

    @Test
    void elTokenExpiraDespuesDeLaVigenciaConfigurada() {
        String token = provider.generateToken(USER_ID, List.of("CONTRATANTE"));

        Instant emitido = provider.getIssuedAtFromToken(token);
        Instant expira = provider.parse(token).getExpiration().toInstant();

        assertEquals(900, expira.getEpochSecond() - emitido.getEpochSecond());
    }

    @Test
    void rechazaUnTokenVencido() {
        JwtProvider caducado = new JwtProvider(SECRETO_A, -1000L);
        String token = caducado.generateToken(USER_ID, List.of("CONTRATANTE"));

        assertFalse(caducado.isValid(token));
        assertThrows(ExpiredJwtException.class, () -> caducado.parse(token));
    }

    @Test
    void rechazaUnTokenFirmadoConOtraClave() {
        JwtProvider ajeno = new JwtProvider(SECRETO_B, QUINCE_MINUTOS_MS);
        String tokenAjeno = ajeno.generateToken(USER_ID, List.of("ADMIN"));

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

        assertThrows(RuntimeException.class, () -> new JwtProvider(corta, QUINCE_MINUTOS_MS));
    }
}