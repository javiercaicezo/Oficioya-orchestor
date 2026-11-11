package eci.edu.dosw.identity.service;

import eci.edu.dosw.identity.exception.WeakPasswordException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Service that enforces password security policies across the application (RF-03).
 * Validates complexity requirements (minimum length, character diversity)
 * and prevents password reuse by comparing new candidates against existing hashes.
 */
@Service
public class PasswordPolicyService {

    public static final int MIN_LENGTH = 12;

    private final PasswordEncoder passwordEncoder;

    /**
     * Constructs a new PasswordPolicyService with the designated password encoder.
     *
     * @param passwordEncoder The {@link PasswordEncoder} used to compare candidate passwords against stored hashes.
     */
    public PasswordPolicyService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Validates password composition rules.
     * The password must satisfy all of the following criteria:
     * <ul>
     *   <li>Cannot be null or blank.</li>
     *   <li>Must contain at least {@value #MIN_LENGTH} characters.</li>
     *   <li>Must include at least one uppercase letter.</li>
     *   <li>Must include at least one lowercase letter.</li>
     *   <li>Must include at least one numeric digit.</li>
     *   <li>Must include at least one special character (non-alphanumeric, non-whitespace).</li>
     * </ul>
     *
     * @param password The candidate plaintext password to evaluate.
     * @throws WeakPasswordException if any of the composition rules are violated,
     *                               detailing all missing requirements.
     */
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
     * Validates a new candidate password against composition policies and ensures it differs
     * from the user's current password.
     *
     * @param newPassword The candidate new plaintext password to evaluate.
     * @param currentHash The BCrypt hash of the user's current password; if null, only composition rules are checked.
     * @throws WeakPasswordException if the password violates composition requirements
     *                               or matches the current password hash.
     */
    public void validateChange(String newPassword, String currentHash) {
        validate(newPassword);
        if (currentHash != null && passwordEncoder.matches(newPassword, currentHash)) {
            throw new WeakPasswordException("La nueva contraseña debe ser diferente a la actual.");
        }
    }
}

