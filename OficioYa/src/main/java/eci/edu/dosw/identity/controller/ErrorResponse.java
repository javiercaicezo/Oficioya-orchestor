package eci.edu.dosw.identity.controller;

public record ErrorResponse(String error, String message) {
    public ErrorResponse(String message) {
        this(message, message);
    }
}

