package eci.edu.dosw.user;

import java.util.Optional;
import java.util.UUID;

/**
 * Contrato del modulo User. Consumido por el orquestador.
 */
public interface UserService {

    Optional<UserDto> findById(UUID id);

    Optional<UserDto> findByEmail(String email);

    /** Crea el perfil en Users y devuelve el usuario con su id (UUID) asignado. */
    UserDto createProfile(NewUser newUser);

    /** Elimina un perfil en Users. Utilizado para compensación ante fallos. */
    void deleteProfile(UUID id);
}
