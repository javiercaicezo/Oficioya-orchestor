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

/**
 * Security component responsible for the lifecycle of JSON Web Tokens (JWT).
 * 
 * Handles the cryptographic signing (HMAC) and validation of JWTs. It encapsulates 
 * user identity (subject) and authorization context (roles) into stateless tokens, 
 * ensuring data integrity and enforcing time-based expiration policies.
 * 
 * Secrets and expiration times are externalized to application properties 
 * to comply with 12-Factor App methodology.
 */
@Component
public class JwtProvider {

    private final SecretKey key;
    private final long expirationMs;

    public JwtProvider(@Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration.ms:1800000}") long expirationMs) {
        // El secreto va en Base64 y debe decodificar a minimo 32 bytes.
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.expirationMs = expirationMs;
    }

    public String generateToken(Long userId, List<String> roles) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claim("roles", roles)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(expirationMs)))
                .signWith(key)
                .compact();
    }

    /**
     * Verifica firma y expiracion. Lanza JwtException si el token no es valido o
     * esta vencido.
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

    public Long getUserIdFromToken(String token) {
        return Long.valueOf(parse(token).getSubject());
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