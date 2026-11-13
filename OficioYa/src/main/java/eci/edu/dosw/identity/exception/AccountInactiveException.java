package eci.edu.dosw.identity.exception;

public class AccountInactiveException extends IdentityException {
    public AccountInactiveException() {
        super("La cuenta se encuentra inactiva o bloqueada.");
    }

    public AccountInactiveException(String message) {
        super(message);
    }
}

