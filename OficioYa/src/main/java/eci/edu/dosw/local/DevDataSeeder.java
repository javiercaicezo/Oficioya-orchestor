package eci.edu.dosw.local;

import eci.edu.dosw.orchestrator.AuthOrchestrator;
import eci.edu.dosw.orchestrator.dto.RegisterRequest;
import eci.edu.dosw.user.Role;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Carga usuarios de prueba al arrancar en perfil local.
 * Solo activo con el perfil "local" (nunca en producción).
 */
@Component
@Profile("local")
public class DevDataSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DevDataSeeder.class);

    private final AuthOrchestrator authOrchestrator;
    private final LocalUserService localUserService;

    public DevDataSeeder(AuthOrchestrator authOrchestrator, LocalUserService localUserService) {
        this.authOrchestrator = authOrchestrator;
        this.localUserService = localUserService;
    }

    @Override
    public void run(ApplicationArguments args) {
        seedUser("Carlos López",    "carlos@oficioya.com",  "Carlos2024!*",   Set.of(Role.CLIENT));
        seedUser("Admin OficioYa",  "admin@oficioya.com",   "Admin2024!*",    Set.of(Role.ADMINISTRATOR));
        log.info("✅ DevDataSeeder: usuarios de prueba cargados.");
    }

    private void seedUser(String name, String email, String password, Set<Role> roles) {
        if (localUserService.findByEmail(email).isPresent()) {
            log.debug("DevDataSeeder: '{}' ya existe, se omite.", email);
            return;
        }
        try {
            authOrchestrator.register(new RegisterRequest(name, email, password, roles));
            log.info("DevDataSeeder: usuario '{}' creado con email '{}'.", name, email);
        } catch (Exception e) {
            log.warn("DevDataSeeder: no se pudo crear '{}': {}", email, e.getMessage());
        }
    }
}

