package eci.edu.dosw.user;

import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.identity.service.JwtProvider;
import eci.edu.dosw.orchestrator.dto.PhoneDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HttpUserServiceTest {

    private JwtProvider jwtProvider;
    private HttpUserService httpUserService;

    @BeforeEach
    void setUp() {
        jwtProvider = mock(JwtProvider.class);
        when(jwtProvider.generateServiceToken()).thenReturn("mock-service-token");
        httpUserService = new HttpUserService("http://localhost:59998", jwtProvider);
    }

    @Test
    void findByIdDevuelveEmptySiFallaConexion() {
        Optional<UserDto> result = httpUserService.findById(UUID.randomUUID());
        assertTrue(result.isEmpty());
    }

    @Test
    void findByEmailDevuelveEmptySiFallaConexion() {
        Optional<UserDto> result = httpUserService.findByEmail("test@x.com");
        assertTrue(result.isEmpty());
    }

    @Test
    void createProfileLanzaExcepcionSiFallaConexion() {
        NewUser newUser = new NewUser("Test", "test@x.com", List.of(new PhoneDTO("+573001234567", true)), List.of("CONTRATANTE"));
        assertThrows(RuntimeException.class, () -> httpUserService.createProfile(newUser));
    }

    @Test
    void deleteProfileManejaErrorSinLanzarExcepcion() {
        httpUserService.deleteProfile(UUID.randomUUID());
        // No debe lanzar excepción
    }
}

