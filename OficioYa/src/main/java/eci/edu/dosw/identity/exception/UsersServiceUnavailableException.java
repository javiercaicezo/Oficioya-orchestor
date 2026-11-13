package eci.edu.dosw.identity.exception;

/**
 * Excepción lanzada cuando el microservicio de Usuarios no responde o devuelve un error del servidor (5xx, conexión, etc.).
 */
public class UsersServiceUnavailableException extends RuntimeException {

    public UsersServiceUnavailableException(String message) {
        super(message);
    }

    public UsersServiceUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}

