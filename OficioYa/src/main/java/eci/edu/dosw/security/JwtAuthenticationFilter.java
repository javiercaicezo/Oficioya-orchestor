package eci.edu.dosw.security;

import eci.edu.dosw.identity.service.CredentialService;
import eci.edu.dosw.identity.service.JwtProvider;
import eci.edu.dosw.user.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

// Sin @Component: si lo tuviera, Spring Boot lo registraria como
// filtro de servlet fuera de la cadena de seguridad.
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String PREFIX = "Bearer ";
    private static final Set<String> ROLES_VALIDOS =
            Arrays.stream(Role.values()).map(Role::name).collect(Collectors.toSet());

    private final JwtProvider jwtProvider;
    private final CredentialService credentialService;

    public JwtAuthenticationFilter(JwtProvider jwtProvider, CredentialService credentialService) {
        this.jwtProvider = jwtProvider;
        this.credentialService = credentialService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(PREFIX)) {
            autenticar(header.substring(PREFIX.length()).trim());
        }
        chain.doFilter(request, response);
    }

    private void autenticar(String token) {
        try {
            Claims claims = jwtProvider.parse(token);
            Date emitido = claims.getIssuedAt();
            if (emitido == null) {
                return;
            }
            Long userId = Long.valueOf(claims.getSubject());
            if (credentialService.wasIssuedBeforePasswordChange(userId, emitido.toInstant())) {
                return;
            }
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(userId, null, autoridades(claims)));
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Token rechazado: {}", e.getClass().getSimpleName());
        }
    }

    private List<SimpleGrantedAuthority> autoridades(Claims claims) {
        List<?> roles = claims.get("roles", List.class);
        if (roles == null) {
            return List.of();
        }
        return roles.stream()
                .map(String::valueOf)
                .filter(ROLES_VALIDOS::contains)
                .map(nombre -> new SimpleGrantedAuthority("ROLE_" + nombre))
                .toList();
    }
}
