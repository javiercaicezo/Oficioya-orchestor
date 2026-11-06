package eci.edu.dosw.security;

import eci.edu.dosw.identity.model.Credential;
import eci.edu.dosw.identity.repository.CredentialRepository;
import eci.edu.dosw.identity.service.CredentialService;
import eci.edu.dosw.identity.service.JwtProvider;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Encoders;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityIntegrationTest {

    private static final Long USER_ID = 1L;
    private static final String CLAVE = "Segura#Clave2026";

    @Autowired private MockMvc mvc;
    @Autowired private JwtProvider jwtProvider;
    @Autowired private CredentialService credentialService;
    @Autowired private CredentialRepository credentialRepository;
    @Autowired private Clock clock;
    @Value("${jwt.secret}") private String secret;

    @BeforeEach
    void preparar() {
        credentialRepository.deleteAll();
        credentialService.create(USER_ID, CLAVE);
    }

    @AfterEach
    void limpiar() {
        credentialRepository.deleteAll();
    }

    private String token(String... roles) {
        return jwtProvider.generateToken(USER_ID, List.of(roles));
    }

    private ResultActions get(String ruta, String token) throws Exception {
        MockHttpServletRequestBuilder req = MockMvcRequestBuilders.get(ruta);
        if (token != null) {
            req.header("Authorization", "Bearer " + token);
        }
        return mvc.perform(req);
    }

    // --- token válido ---
    @Test
    void unTokenValidoPasaYElControladorVeElIdDelToken() throws Exception {
        get("/api/probe", token("CLIENT")).andExpect(status().isOk()).andExpect(content().string("1"));
    }

    // --- sin token / inválido ---
    @Test
    void sinTokenEnRutaProtegidaDevuelve401() throws Exception {
        get("/api/probe", null).andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer"));
    }

    @Test
    void headerQueNoEsBearerDevuelve401() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/api/probe").header("Authorization", "Basic abc"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenMalformadoDevuelve401() throws Exception {
        get("/api/probe", "esto.no.es.un.jwt").andExpect(status().isUnauthorized());
    }

    @Test
    void tokenVacioDevuelve401() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/api/probe").header("Authorization", "Bearer "))
                .andExpect(status().isUnauthorized());
    }

    // --- vencido ---
    @Test
    void tokenVencidoDevuelve401() throws Exception {
        String vencido = new JwtProvider(secret, -1000L).generateToken(USER_ID, List.of("CLIENT"));
        get("/api/probe", vencido).andExpect(status().isUnauthorized());
    }

    // --- manipulado ---
    @Test
    void tokenFirmadoConOtraClaveDevuelve401() throws Exception {
        String otraClave = Encoders.BASE64.encode(Jwts.SIG.HS256.key().build().getEncoded());
        String ajeno = new JwtProvider(otraClave, 1_800_000L).generateToken(USER_ID, List.of("ADMINISTRATOR"));
        get("/api/admin/probe", ajeno).andExpect(status().isUnauthorized());
    }

    @Test
    void cambiarElRolDentroDelTokenInvalidaLaFirma() throws Exception {
        String[] partes = token("CLIENT").split("\\.");
        String original = new String(Base64.getUrlDecoder().decode(partes[1]), UTF_8);
        String alterado = original.replace("\"CLIENT\"", "\"ADMINISTRATOR\"");
        assertNotEquals(original, alterado);
        String falso = partes[0] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(alterado.getBytes(UTF_8))
                + "." + partes[2];
        get("/api/admin/probe", falso).andExpect(status().isUnauthorized());
    }

    // --- roles (RF-07) ---
    @Test
    void elRolCorrectoAccedeALaRutaDeRol() throws Exception {
        get("/api/admin/probe", token("ADMINISTRATOR")).andExpect(status().isOk());
        get("/api/worker/probe", token("WORKER")).andExpect(status().isOk());
    }

    @Test
    void unRolInsuficienteRecibe403() throws Exception {
        get("/api/admin/probe", token("CLIENT")).andExpect(status().isForbidden());
    }

    @Test
    void sinRutaDeRolYSinTokenDevuelve401() throws Exception {
        get("/api/admin/probe", null).andExpect(status().isUnauthorized());
    }

    @Test
    void unTokenSinRolesAutenticaPeroNoPasaLasRutasDeRol() throws Exception {
        String sinRol = token();
        get("/api/probe", sinRol).andExpect(status().isOk());
        get("/api/admin/probe", sinRol).andExpect(status().isForbidden());
        get("/api/worker/probe", sinRol).andExpect(status().isForbidden());
    }

    @Test
    void rolesDesconocidosEnElTokenSeIgnoran() throws Exception {
        get("/api/admin/probe", token("SUPERUSER")).andExpect(status().isForbidden());
    }

    // --- contraseña cambiada ---
    @Test
    void unTokenEmitidoAntesDelCambioDeContrasenaDevuelve401() throws Exception {
        String viejo = token("CLIENT");
        Credential c = credentialRepository.findByUserId(USER_ID).orElseThrow();
        c.setPasswordChangedAt(LocalDateTime.now(clock).plusMinutes(5));
        credentialRepository.save(c);
        get("/api/probe", viejo).andExpect(status().isUnauthorized());
    }

    @Test
    void unTokenDelMismoSegundoDelCambioSigueValido() throws Exception {
        String nuevo = token("CLIENT");
        Instant iat = jwtProvider.getIssuedAtFromToken(nuevo);
        Credential c = credentialRepository.findByUserId(USER_ID).orElseThrow();
        c.setPasswordChangedAt(LocalDateTime.ofInstant(iat, clock.getZone()).plusNanos(500_000_000));
        credentialRepository.save(c);
        get("/api/probe", nuevo).andExpect(status().isOk());
    }

    @Test
    void unTokenDeUnUsuarioSinCredencialDevuelve401() throws Exception {
        String t = token("CLIENT");
        credentialRepository.deleteAll();
        get("/api/probe", t).andExpect(status().isUnauthorized());
    }

    // --- rutas públicas ---
    @Test
    void lasRutasPublicasNoExigenToken() throws Exception {
        for (String ruta : List.of("/api/auth/login", "/api/auth/register",
                "/api/auth/forgot-password", "/api/auth/reset-password")) {
            mvc.perform(MockMvcRequestBuilders.post(ruta))
                    .andExpect(result -> assertNotEquals(401, result.getResponse().getStatus()));
        }
    }

    @Test
    void unTokenVencidoEnUnaRutaPublicaNoLaBloquea() throws Exception {
        String vencido = new JwtProvider(secret, -1000L).generateToken(USER_ID, List.of("CLIENT"));
        mvc.perform(MockMvcRequestBuilders.post("/api/auth/login")
                        .header("Authorization", "Bearer " + vencido))
                .andExpect(result -> assertNotEquals(401, result.getResponse().getStatus()));
    }

    @Test
    void unaRutaNoListadaExigeToken() throws Exception {
        get("/api/cualquier-cosa", null).andExpect(status().isUnauthorized());
    }
}
