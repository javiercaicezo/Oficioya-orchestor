package eci.edu.dosw.local;

import eci.edu.dosw.identity.repository.CredentialRepository;
import eci.edu.dosw.identity.service.CredentialService;
import eci.edu.dosw.orchestrator.dto.PhoneDTO;
import eci.edu.dosw.user.NewUser;
import eci.edu.dosw.user.UserDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Carga usuarios de prueba al arrancar en perfil local.
 * Solo activo con el perfil "local" (nunca en producción).
 */
@Component
@Profile("local")
public class DevDataSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DevDataSeeder.class);

    private final LocalUserService localUserService;
    private final CredentialService credentialService;
    private final CredentialRepository credentialRepository;

    public DevDataSeeder(LocalUserService localUserService, CredentialService credentialService,
            CredentialRepository credentialRepository) {
        this.localUserService = localUserService;
        this.credentialService = credentialService;
        this.credentialRepository = credentialRepository;
    }

    @Override
    public void run(ApplicationArguments args) {
        credentialRepository.deleteAll();
        log.warn("DevDataSeeder: credenciales anteriores eliminadas (perfil local, usuarios en memoria).");

        int cargados = 0;
        cargados += seedUser("Carlos López", "carlos@oficioya.com", "Carlos2024!*", List.of("CONTRATANTE"));
        cargados += seedUser("Admin OficioYa", "admin@oficioya.com", "Admin2024!*Dev", List.of("ADMIN"));
        log.info("DevDataSeeder: {} usuarios de prueba cargados.", cargados);
    }

    private int seedUser(String name, String email, String password, List<String> roles) {
        try {
            UserDto usuario = localUserService.findByEmail(email)
                    .orElseGet(() -> localUserService.createProfile(new NewUser(
                            name,
                            email,
                            List.of(new PhoneDTO("3001234567", true)),
                            roles)));
            if (credentialService.exists(usuario.id())) {
                return 0;
            }
            credentialService.create(usuario.id(), usuario.email(), password);
            log.info("DevDataSeeder: usuario de prueba creado con userId={}.", usuario.id());
            return 1;
        } catch (RuntimeException e) {
            log.warn("DevDataSeeder: no se pudo crear un usuario de prueba: {}", e.getMessage());
            return 0;
        }
    }
}
