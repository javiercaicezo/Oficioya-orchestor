package eci.edu.dosw.orchestrator.dto;

import jakarta.validation.constraints.NotBlank;

public record PhoneDTO(
        @NotBlank(message = "El número de teléfono es obligatorio") String number,
        boolean principal) {
}

