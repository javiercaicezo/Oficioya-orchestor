package eci.edu.dosw.identity.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Security component responsible for the lifecycle of JSON Web Tokens (JWT).
 */
@Component
public class JwtProvider {

    public static final String SERVICE_SUBJECT = "00000000-0000-0000-0000-000000000001";

    private final SecretKey key;
    private final long expirationMs;

    public JwtProvider(@Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration.ms:900000}") long expirationMs) {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.expirationMs = expirationMs;
    }

    /**
     * Genera un token JWT para usuarios finales. El subject es el UUID y los roles
     * no incluyen SERVICE.
     */
    public String generateToken(UUID userId, List<String> roles) {
        List<String> userRoles = roles == null ? List.of()
                : roles.stream()
                        .filter(r -> !r.equalsIgnoreCase("SERVICE"))
                        .toList();
        return generateToken(userId.toString(), userRoles);
    }

    /**
     * Genera un token JWT con subject y roles específicos.
     */
    public String generateToken(String subject, List<String> roles) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(subject)
                .claim("roles", roles)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(expirationMs)))
                .signWith(key)
                .compact();
    }

    /**
     * Genera un token interno del Orquestador con rol SERVICE para llamadas
     * inter-servicio.
     */
    public String generateServiceToken() {
        return generateToken(SERVICE_SUBJECT, List.of("SERVICE"));
    }

    /**
     * Verifica firma y expiración. Lanza JwtException si el token no es válido o
     * está vencido.
     */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isValid(String token) {
        try {
            parse(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public UUID getUserIdFromToken(String token) {
        return UUID.fromString(parse(token).getSubject());
    }

    public String getSubjectFromToken(String token) {
        return parse(token).getSubject();
    }

    @SuppressWarnings("unchecked")
    public List<String> getRolesFromToken(String token) {
        List<String> roles = parse(token).get("roles", List.class);
        return roles == null ? List.of() : roles;
    }

    public Instant getIssuedAtFromToken(String token) {
        return parse(token).getIssuedAt().toInstant();
    }

    public long getExpirationSeconds() {
        return expirationMs / 1000;
    }
}
