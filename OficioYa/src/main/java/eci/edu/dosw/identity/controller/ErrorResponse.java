package eci.edu.dosw.identity.controller;

/**
 * Standardized Data Transfer Object (DTO) for API error responses.
 * Used globally to format HTTP error payloads consistently across the application,
 * providing the frontend with predictable 'error' and 'message' fields.
 */
public record ErrorResponse(String error, String message) {
    public ErrorResponse(String message) {
        this(message, message);
    }
}
