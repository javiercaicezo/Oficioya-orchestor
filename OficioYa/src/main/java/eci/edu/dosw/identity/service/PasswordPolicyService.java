package eci.edu.dosw.identity.service;

import eci.edu.dosw.identity.exception.WeakPasswordException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Política de contraseñas: mínimo 12 caracteres, con mayúscula, minúscula, número y carácter especial,
 * y distinta de la contraseña actual.
 */
@Service
public class PasswordPolicyService {

    public static final int MIN_LENGTH = 12;

    private final PasswordEncoder passwordEncoder;

    public PasswordPolicyService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    /** Valida solo las reglas de composición. Lanza WeakPasswordException si no se cumplen. */
    public void validate(String password) {
        List<String> faltantes = new ArrayList<>();

        if (password == null || password.isBlank()) {
            throw new WeakPasswordException("La contraseña no puede estar vacia.");
        }
        if (password.length() < MIN_LENGTH) {
            faltantes.add("al menos " + MIN_LENGTH + " caracteres");
        }
        if (password.chars().noneMatch(Character::isUpperCase)) {
            faltantes.add("una letra mayuscula");
        }
        if (password.chars().noneMatch(Character::isLowerCase)) {
            faltantes.add("una letra minuscula");
        }
        if (password.chars().noneMatch(Character::isDigit)) {
            faltantes.add("un numero");
        }
        if (password.chars().noneMatch(c -> !Character.isLetterOrDigit(c) && !Character.isWhitespace(c))) {
            faltantes.add("un caracter especial");
        }

        if (!faltantes.isEmpty()) {
            throw new WeakPasswordException("La contraseña debe tener " + String.join(", ", faltantes) + ".");
        }
    }

    /**
     * Valida una contraseña nueva además de que sea distinta de la actual.
     *
     * @param currentHash hash BCrypt de la contraseña actual; si es null solo se validan las reglas
     */
    public void validateChange(String newPassword, String currentHash) {
        validate(newPassword);
        if (currentHash != null && passwordEncoder.matches(newPassword, currentHash)) {
            throw new WeakPasswordException("La nueva contraseña debe ser diferente a la actual.");
        }
    }
}

