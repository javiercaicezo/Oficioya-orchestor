package eci.edu.dosw.user;

import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.identity.exception.UsersServiceUnavailableException;
import eci.edu.dosw.identity.service.JwtProvider;
import eci.edu.dosw.orchestrator.dto.PhoneDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class HttpUserServiceTest {

    private JwtProvider jwtProvider;
    private MockRestServiceServer mockServer;
    private HttpUserService httpUserService;

    @BeforeEach
    void setUp() {
        jwtProvider = mock(JwtProvider.class);
        when(jwtProvider.generateServiceToken()).thenReturn("mock-service-token");

        RestClient.Builder builder = RestClient.builder().baseUrl("http://localhost:8080");
        mockServer = MockRestServiceServer.bindTo(builder).build();
        RestClient restClient = builder.build();

        httpUserService = new HttpUserService(restClient, jwtProvider);
    }

    @Test
    void findByIdDevuelveEmptySiResponde404() {
        UUID id = UUID.randomUUID();
        mockServer.expect(requestTo("http://localhost:8080/api/v1/users/" + id + "/account"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer mock-service-token"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        Optional<UserDto> result = httpUserService.findById(id);

        assertTrue(result.isEmpty());
        mockServer.verify();
    }

    @Test
    void findByIdLanzaUsersServiceUnavailableExceptionSiResponde500() {
        UUID id = UUID.randomUUID();
        mockServer.expect(requestTo("http://localhost:8080/api/v1/users/" + id + "/account"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withServerError());

        assertThrows(UsersServiceUnavailableException.class, () -> httpUserService.findById(id));
        mockServer.verify();
    }

    @Test
    void findByEmailDevuelveEmptySiResponde404() {
        mockServer.expect(requestTo("http://localhost:8080/api/v1/users/by-email?email=test@x.com"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer mock-service-token"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        Optional<UserDto> result = httpUserService.findByEmail("test@x.com");

        assertTrue(result.isEmpty());
        mockServer.verify();
    }

    @Test
    void findByEmailLanzaUsersServiceUnavailableExceptionSiResponde500() {
        mockServer.expect(requestTo("http://localhost:8080/api/v1/users/by-email?email=test@x.com"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withServerError());

        assertThrows(UsersServiceUnavailableException.class, () -> httpUserService.findByEmail("test@x.com"));
        mockServer.verify();
    }

    @Test
    void createProfileLanzaDuplicateUserExceptionSiResponde409() {
        NewUser newUser = new NewUser("Test", "test@x.com", List.of(new PhoneDTO("+573001234567", true)), List.of("CONTRATANTE"));

        mockServer.expect(requestTo("http://localhost:8080/api/v1/users"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("Authorization", "Bearer mock-service-token"))
                .andRespond(withStatus(HttpStatus.CONFLICT));

        assertThrows(DuplicateUserException.class, () -> httpUserService.createProfile(newUser));
        mockServer.verify();
    }

    @Test
    void createProfileLanzaIllegalArgumentExceptionConMensajeDeUsersSiResponde400() {
        NewUser newUser = new NewUser("Test", "test@x.com", List.of(new PhoneDTO("+573001234567", true)), List.of("CONTRATANTE"));
        String errorJson = """
                {
                    "timestamp": "2026-11-12T16:00:00Z",
                    "status": 400,
                    "error": "Bad Request",
                    "message": "El formato del teléfono es inválido",
                    "route": "/api/v1/users"
                }
                """;

        mockServer.expect(requestTo("http://localhost:8080/api/v1/users"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("Authorization", "Bearer mock-service-token"))
                .andRespond(withStatus(HttpStatus.BAD_REQUEST)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(errorJson));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> httpUserService.createProfile(newUser));

        assertEquals("El formato del teléfono es inválido", ex.getMessage());
        mockServer.verify();
    }

    @Test
    void createProfileLanzaIllegalArgumentExceptionConMensajeGenericoSiNoHayMessageEnCuerpo() {
        NewUser newUser = new NewUser("Test", "test@x.com", List.of(new PhoneDTO("+573001234567", true)), List.of("CONTRATANTE"));

        mockServer.expect(requestTo("http://localhost:8080/api/v1/users"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withStatus(HttpStatus.BAD_REQUEST).body("{}"));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> httpUserService.createProfile(newUser));

        assertEquals("Datos de usuario inválidos", ex.getMessage());
        mockServer.verify();
    }

    @Test
    void deleteProfileEjecutaCorrectamente() {
        UUID id = UUID.randomUUID();
        mockServer.expect(requestTo("http://localhost:8080/api/v1/users/" + id))
                .andExpect(method(HttpMethod.DELETE))
                .andExpect(header("Authorization", "Bearer mock-service-token"))
                .andRespond(withStatus(HttpStatus.NO_CONTENT));

        assertDoesNotThrow(() -> httpUserService.deleteProfile(id));
        mockServer.verify();
    }

    @Test
    void deleteProfileManejaErrorSinLanzarExcepcion() {
        UUID id = UUID.randomUUID();
        mockServer.expect(requestTo("http://localhost:8080/api/v1/users/" + id))
                .andExpect(method(HttpMethod.DELETE))
                .andRespond(withServerError());

        assertDoesNotThrow(() -> httpUserService.deleteProfile(id));
        mockServer.verify();
    }
}
