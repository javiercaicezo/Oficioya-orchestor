package eci.edu.dosw.local;

import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.user.NewUser;
import eci.edu.dosw.user.Role;
import eci.edu.dosw.user.UserDto;
import eci.edu.dosw.user.UserService;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Implementacion TEMPORAL en memoria del modulo User, para desarrollo y
 * pruebas.
 * Se reemplaza por la del equipo de Usuarios cuando exista.
 */
@Service
@Profile({ "local", "test", "default" })
public class LocalUserService implements UserService {

    private final Map<Long, UserDto> usuarios = new ConcurrentHashMap<>();
    private final AtomicLong secuencia = new AtomicLong(0);

    @Override
    public Optional<UserDto> findById(Long id) {
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
        Set<Role> roles = newUser.roles() == null ? Set.of() : Set.copyOf(newUser.roles());
        UserDto creado = new UserDto(secuencia.incrementAndGet(), newUser.name(), newUser.email().trim(), roles, true);
        usuarios.put(creado.id(), creado);
        return creado;
    }

    @Override
    public void deleteProfile(Long id) {
        usuarios.remove(id);
    }

    /** Solo para pruebas: marca al usuario como inactivo. */
    public void deactivate(Long id) {
        usuarios.computeIfPresent(id,
                (k, u) -> new UserDto(u.id(), u.name(), u.email(), u.roles(), false));
    }

    /** Solo para pruebas: vacia los usuarios y reinicia los ids. */
    public synchronized void clear() {
        usuarios.clear();
        secuencia.set(0);
    }

    private static String normalizar(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
