package eci.edu.dosw.local;

import eci.edu.dosw.identity.repository.CredentialRepository;
import eci.edu.dosw.identity.service.CredentialService;
import eci.edu.dosw.user.NewUser;
import eci.edu.dosw.user.Role;
import eci.edu.dosw.user.UserDto;
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
 *
 * Crea el perfil y la credencial directamente (sin pasar por el orquestador) porque
 * el registro público rechaza el rol ADMINISTRATOR. Los usuarios viven en memoria y sus
 * ids reinician en cada arranque, pero las credenciales quedan en la base de datos:
 * por eso se borran antes de sembrar, para que no choquen con los ids nuevos.
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
        cargados += seedUser("Carlos López", "carlos@oficioya.com", "Carlos2024!*", Set.of(Role.CLIENT));
        cargados += seedUser("Admin OficioYa", "admin@oficioya.com", "Admin2024!*Dev", Set.of(Role.ADMINISTRATOR));
        log.info("DevDataSeeder: {} usuarios de prueba cargados.", cargados);
    }

    private int seedUser(String name, String email, String password, Set<Role> roles) {
        try {
            UserDto usuario = localUserService.findByEmail(email)
                    .orElseGet(() -> localUserService.createProfile(new NewUser(name, email, roles)));
            if (credentialService.exists(usuario.id())) {
                return 0;
            }
            credentialService.create(usuario.id(), password);
            log.info("DevDataSeeder: usuario de prueba creado con userId={}.", usuario.id());
            return 1;
        } catch (RuntimeException e) {
            log.warn("DevDataSeeder: no se pudo crear un usuario de prueba: {}", e.getMessage());
            return 0;
        }
    }
}
