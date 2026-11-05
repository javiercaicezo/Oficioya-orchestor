package eci.edu.dosw.user;

import java.util.Optional;

/**
 * Contrato del modulo User (de otro equipo). Identity no lo implementa: lo
 * consume
 * el orquestador, que es el unico que coordina los modulos (OR-03).
 */
public interface UserService {

    Optional<UserDto> findById(Long id);

    Optional<UserDto> findByEmail(String email);

    /** Crea el perfil y devuelve el usuario con su id asignado. */
    UserDto createProfile(NewUser newUser);

    /**
     * Elimina un perfil. El orquestador lo usa para deshacer un registro que fallo
     * a la mitad.
     */
    void deleteProfile(Long id);
}
