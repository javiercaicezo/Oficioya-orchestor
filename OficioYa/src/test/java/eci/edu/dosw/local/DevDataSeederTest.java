package eci.edu.dosw.local;

import eci.edu.dosw.identity.repository.CredentialRepository;
import eci.edu.dosw.orchestrator.AuthOrchestrator;
import eci.edu.dosw.orchestrator.dto.LoginRequest;
import eci.edu.dosw.user.Role;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * El seeder solo existe con el perfil "local"; se combina con "test" para usar la base H2.
 */
@SpringBootTest
@ActiveProfiles({ "test", "local" })
class DevDataSeederTest {

    @Autowired private DevDataSeeder seeder;
    @Autowired private LocalUserService localUserService;
    @Autowired private CredentialRepository credentialRepository;
    @Autowired private AuthOrchestrator orchestrator;

    @BeforeEach
    void sembrarDeNuevo() {
        localUserService.clear();
        credentialRepository.deleteAll();
        seeder.run(null);
    }

    @AfterEach
    void limpiar() {
        localUserService.clear();
        credentialRepository.deleteAll();
    }

    @Test
    void creaAlClienteYAlAdministradorQuePuedenIniciarSesion() {
        var cliente = orchestrator.login(new LoginRequest("carlos@oficioya.com", "Carlos2024!*"));
        var admin = orchestrator.login(new LoginRequest("admin@oficioya.com", "Admin2024!*Dev"));

        assertTrue(cliente.roles().contains("CONTRATANTE"));
        assertTrue(admin.roles().contains("ADMIN"));
    }

    @Test
    void correrElSeederOtraVezNoDuplicaNiDejaCredencialesHuerfanas() {
        seeder.run(null);

        assertEquals(2, credentialRepository.count());
        assertTrue(orchestrator.login(new LoginRequest("admin@oficioya.com", "Admin2024!*Dev"))
                .roles().contains("ADMIN"));
    }

    @Test
    void despuesDeUnReinicioLasCredencialesViejasNoChocanConLosIdsNuevos() {
        // Reinicio: los usuarios en memoria se pierden y sus ids vuelven a empezar,
        // pero las credenciales anteriores siguen en la base de datos.
        localUserService.clear();
        seeder.run(null);

        assertEquals(2, credentialRepository.count());
        assertTrue(orchestrator.login(new LoginRequest("carlos@oficioya.com", "Carlos2024!*"))
                .roles().contains("CONTRATANTE"));
    }
}
