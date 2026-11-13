package eci.edu.dosw.orchestrator.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import java.util.List;

public record RegisterRequest(
        @NotBlank(message = "El nombre es obligatorio") String name,
        @NotBlank(message = "El correo es obligatorio") @Email(message = "El formato de correo no es válido") String email,
        @NotBlank(message = "La contraseña es obligatoria") String password,
        @NotEmpty(message = "Debe ingresar al menos un teléfono") List<@Valid PhoneDTO> phones,
        @NotEmpty(message = "Debe seleccionar al menos un rol") List<String> roles) {

    public RegisterRequest {
        if (phones != null) {
            if (phones.isEmpty()) {
                throw new IllegalArgumentException("Debe ingresar al menos un teléfono");
            }
            if (phones.size() > 3) {
                throw new IllegalArgumentException("No puede ingresar más de 3 teléfonos");
            }
            long principalCount = phones.stream().filter(PhoneDTO::principal).count();
            if (principalCount != 1) {
                throw new IllegalArgumentException("Exactamente un teléfono debe ser marcado como principal");
            }
        }
    }
}
