package eci.edu.dosw.orchestrator.dto;

import java.util.List;
import java.util.UUID;

public record LoginResponse(String token, long expiresInSeconds, UUID userId, List<String> roles) {
}
