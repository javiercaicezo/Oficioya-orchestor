package eci.edu.dosw.identity.exception;

public class ForbiddenRoleException extends IdentityException {

    public ForbiddenRoleException() {
        super("No es posible registrarse con el rol ADMIN.");
    }

    public ForbiddenRoleException(String message) {
        super(message);
    }
}