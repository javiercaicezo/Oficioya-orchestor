package eci.edu.dosw.local;

import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.user.NewUser;
import eci.edu.dosw.user.UserDto;
import eci.edu.dosw.user.UserService;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementación en memoria del módulo User para pruebas locales y tests automatizados.
 */
@Service
@Profile({ "local", "test" })
public class LocalUserService implements UserService {

    private final Map<UUID, UserDto> usuarios = new ConcurrentHashMap<>();

    @Override
    public Optional<UserDto> findById(UUID id) {
        return Optional.ofNullable(usuarios.get(id));
    }

    @Override
    public Optional<UserDto> findByEmail(String email) {
        if (email == null) {
            return Optional.empty();
        }
        String buscado = normalizar(email);
        return usuarios.values().stream()
                .filter(u -> normalizar(u.email()).equals(buscado))
                .findFirst();
    }

    @Override
    public synchronized UserDto createProfile(NewUser newUser) {
        if (findByEmail(newUser.email()).isPresent()) {
            throw new DuplicateUserException();
        }
        List<String> roles = newUser.roles() == null ? List.of() : List.copyOf(newUser.roles());
        UUID id = UUID.randomUUID();
        UserDto creado = new UserDto(id, newUser.name(), newUser.email().trim(), newUser.phones(), roles, "ACTIVE");
        usuarios.put(creado.id(), creado);
        return creado;
    }

    @Override
    public void deleteProfile(UUID id) {
        usuarios.remove(id);
    }

    /** Solo para pruebas: marca al usuario como inactivo. */
    public void deactivate(UUID id) {
        usuarios.computeIfPresent(id,
                (k, u) -> new UserDto(u.id(), u.name(), u.email(), u.phones(), u.roles(), "INACTIVE", false));
    }

    /** Solo para pruebas: vacía los usuarios. */
    public synchronized void clear() {
        usuarios.clear();
    }

    private static String normalizar(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
