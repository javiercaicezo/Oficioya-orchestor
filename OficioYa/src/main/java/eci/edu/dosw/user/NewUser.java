package eci.edu.dosw.user;

import eci.edu.dosw.orchestrator.dto.PhoneDTO;
import java.util.List;

/**
 * Datos para crear un perfil en el modulo User (POST /api/v1/users).
 */
public record NewUser(String name, String email, List<PhoneDTO> phones, List<String> roles) {
}
