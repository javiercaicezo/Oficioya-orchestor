package eci.edu.dosw.user;

import eci.edu.dosw.orchestrator.dto.PhoneDTO;
import java.util.List;
import java.util.UUID;

/**
 * Perfil de usuario tal como lo expone el modulo User.
 */
public record UserDto(
        UUID id,
        String name,
        String email,
        List<PhoneDTO> phones,
        List<String> roles,
        String accountStatus,
        boolean active) {

    public UserDto(UUID id, String name, String email, List<String> roles, String accountStatus) {
        this(id, name, email, List.of(), roles, accountStatus, isStatusActive(accountStatus));
    }

    public UserDto(UUID id, String name, String email, List<PhoneDTO> phones, List<String> roles, String accountStatus) {
        this(id, name, email, phones, roles, accountStatus, isStatusActive(accountStatus));
    }

    public boolean isActive() {
        return active || isStatusActive(accountStatus);
    }

    private static boolean isStatusActive(String status) {
        return status != null && (status.equalsIgnoreCase("ACTIVE") || status.equalsIgnoreCase("ACTIVO"));
    }
}
