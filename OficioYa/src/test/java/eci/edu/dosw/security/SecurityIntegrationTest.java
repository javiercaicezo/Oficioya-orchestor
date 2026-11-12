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

import eci.edu.dosw.local.LocalUserService;
import eci.edu.dosw.user.NewUser;
import eci.edu.dosw.user.Role;
import eci.edu.dosw.user.UserDto;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertTrue;
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

    @Autowired
    private MockMvc mvc;
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private CredentialService credentialService;
    @Autowired
    private CredentialRepository credentialRepository;
    @Autowired
    private Clock clock;
    @Value("${jwt.secret}")
    private String secret;

    @Autowired
    private LocalUserService localUserService;
    @Autowired
    private PasswordEncoder passwordEncoder;

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
        get("/api/probe", token("CONTRATANTE")).andExpect(status().isOk()).andExpect(content().string("1"));
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
        String vencido = new JwtProvider(secret, -1000L).generateToken(USER_ID, List.of("CONTRATANTE"));
        get("/api/probe", vencido).andExpect(status().isUnauthorized());
    }

    // --- manipulado ---
    @Test
    void tokenFirmadoConOtraClaveDevuelve401() throws Exception {
        String otraClave = Encoders.BASE64.encode(Jwts.SIG.HS256.key().build().getEncoded());
        String ajeno = new JwtProvider(otraClave, 1_800_000L).generateToken(USER_ID, List.of("ADMIN"));
        get("/api/admin/probe", ajeno).andExpect(status().isUnauthorized());
    }

    @Test
    void cambiarElRolDentroDelTokenInvalidaLaFirma() throws Exception {
        String[] partes = token("CONTRATANTE").split("\\.");
        String original = new String(Base64.getUrlDecoder().decode(partes[1]), UTF_8);
        String alterado = original.replace("\"CONTRATANTE\"", "\"ADMIN\"");
        assertNotEquals(original, alterado);
        String falso = partes[0] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(alterado.getBytes(UTF_8))
                + "." + partes[2];
        get("/api/admin/probe", falso).andExpect(status().isUnauthorized());
    }

    // --- roles (RF-07) ---
    @Test
    void elRolCorrectoAccedeALaRutaDeRol() throws Exception {
        get("/api/admin/probe", token("ADMIN")).andExpect(status().isOk());
        get("/api/worker/probe", token("TRABAJADOR")).andExpect(status().isOk());
    }

    @Test
    void unRolInsuficienteRecibe403() throws Exception {
        get("/api/admin/probe", token("CONTRATANTE")).andExpect(status().isForbidden());
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
        String viejo = token("CONTRATANTE");
        Credential c = credentialRepository.findByUserId(USER_ID).orElseThrow();
        c.setPasswordChangedAt(LocalDateTime.now(clock).plusMinutes(5));
        credentialRepository.save(c);
        get("/api/probe", viejo).andExpect(status().isUnauthorized());
    }

    @Test
    void unTokenDelMismoSegundoDelCambioSigueValido() throws Exception {
        String nuevo = token("CONTRATANTE");
        Instant iat = jwtProvider.getIssuedAtFromToken(nuevo);
        Credential c = credentialRepository.findByUserId(USER_ID).orElseThrow();
        c.setPasswordChangedAt(LocalDateTime.ofInstant(iat, clock.getZone()).plusNanos(500_000_000));
        credentialRepository.save(c);
        get("/api/probe", nuevo).andExpect(status().isOk());
    }

    @Test
    void unTokenDeUnUsuarioSinCredencialDevuelve401() throws Exception {
        String t = token("CONTRATANTE");
        credentialRepository.deleteAll();
        get("/api/probe", t).andExpect(status().isUnauthorized());
    }

    // --- rutas públicas ---
    @Test
    void lasRutasPublicasNoExigenToken() throws Exception {
        for (String ruta : List.of("/api/v1/auth/login", "/api/v1/auth/register",
                "/api/v1/auth/forgot", "/api/v1/auth/reset")) {
            mvc.perform(MockMvcRequestBuilders.post(ruta))
                    .andExpect(result -> assertNotEquals(401, result.getResponse().getStatus()));
        }
    }

    @Test
    void lasRutasViejasSinVersionYaNoSonPublicas() throws Exception {
        for (String ruta : List.of("/api/auth/login", "/api/auth/register",
                "/api/auth/forgot-password", "/api/auth/reset-password")) {
            mvc.perform(MockMvcRequestBuilders.post(ruta))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Test
    void unTokenVencidoEnUnaRutaPublicaNoLaBloquea() throws Exception {
        String vencido = new JwtProvider(secret, -1000L).generateToken(USER_ID, List.of("CONTRATANTE"));
        mvc.perform(MockMvcRequestBuilders.post("/api/v1/auth/login")
                .header("Authorization", "Bearer " + vencido))
                .andExpect(result -> assertNotEquals(401, result.getResponse().getStatus()));
    }

    @Test
    void unaRutaNoListadaExigeToken() throws Exception {
        get("/api/cualquier-cosa", null).andExpect(status().isUnauthorized());
    }

    // --- cambio de contraseña: el id sale del token, no de la URL ---
    private UserDto crearUsuarioConCredencial(String clave) {
        UserDto usuario = localUserService.createProfile(
                new NewUser("Prueba", UUID.randomUUID() + "@test.com", Set.of(Role.CONTRATANTE)));
        credentialService.create(usuario.id(), clave);
        return usuario;
    }

    @Test
    void cambiarContrasenaSinTokenDevuelve401() throws Exception {
        mvc.perform(MockMvcRequestBuilders.put("/api/v1/auth/change")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\":\"x\",\"newPassword\":\"y\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void cambiarContrasenaIgnoraElUserIdDeLaUrl() throws Exception {
        credentialRepository.deleteAll();
        String claveVictima = "Victima#Clave2026";
        UserDto atacante = crearUsuarioConCredencial(CLAVE);
        UserDto victima = crearUsuarioConCredencial(claveVictima);
        String tokenAtacante = jwtProvider.generateToken(atacante.id(), List.of("CONTRATANTE"));

        mvc.perform(MockMvcRequestBuilders.put("/api/v1/auth/change")
                .param("userId", String.valueOf(victima.id()))
                .header("Authorization", "Bearer " + tokenAtacante)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\":\"" + CLAVE
                        + "\",\"newPassword\":\"Nueva#Clave2026X\"}"))
                .andExpect(status().isOk());

        String hashVictima = credentialRepository.findByUserId(victima.id()).orElseThrow().getPasswordHash();
        String hashAtacante = credentialRepository.findByUserId(atacante.id()).orElseThrow().getPasswordHash();
        assertTrue(passwordEncoder.matches(claveVictima, hashVictima));
        assertTrue(passwordEncoder.matches("Nueva#Clave2026X", hashAtacante));

        localUserService.deleteProfile(atacante.id());
        localUserService.deleteProfile(victima.id());
    }
}
