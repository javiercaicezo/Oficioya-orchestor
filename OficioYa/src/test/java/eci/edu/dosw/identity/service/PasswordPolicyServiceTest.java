package eci.edu.dosw.identity.service;

import eci.edu.dosw.identity.exception.WeakPasswordException;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Prueba unitaria pura: no levanta Spring. */
class PasswordPolicyServiceTest {

    private static final String VALIDA = "Segura#Clave2026";

    private final PasswordEncoder encoder = new BCryptPasswordEncoder();
    private final PasswordPolicyService policy = new PasswordPolicyService(encoder);

    private String mensajeDe(String password) {
        return assertThrows(WeakPasswordException.class, () -> policy.validate(password)).getMessage();
    }

    @Test
    void aceptaUnaContrasenaQueCumpleTodo() {
        assertDoesNotThrow(() -> policy.validate(VALIDA));
    }

    @Test
    void rechazaContrasenaNula() {
        assertThrows(WeakPasswordException.class, () -> policy.validate(null));
    }

    @Test
    void rechazaContrasenaEnBlanco() {
        assertThrows(WeakPasswordException.class, () -> policy.validate("   "));
    }

    @Test
    void rechazaContrasenaCorta() {
        assertTrue(mensajeDe("Ab1#cde").contains("12 caracteres"));
    }

    @Test
    void aceptaExactamenteDoceCaracteres() {
        assertDoesNotThrow(() -> policy.validate("Abcdefgh1#xy"));
    }

    @Test
    void rechazaSinMayuscula() {
        assertTrue(mensajeDe("segura#clave2026").contains("mayuscula"));
    }

    @Test
    void rechazaSinMinuscula() {
        assertTrue(mensajeDe("SEGURA#CLAVE2026").contains("minuscula"));
    }

    @Test
    void rechazaSinNumero() {
        assertTrue(mensajeDe("Segura#ClaveAbcd").contains("numero"));
    }

    @Test
    void rechazaSinCaracterEspecial() {
        assertTrue(mensajeDe("SeguraClave2026").contains("especial"));
    }

    @Test
    void elEspacioNoCuentaComoCaracterEspecial() {
        assertTrue(mensajeDe("Segura Clave2026").contains("especial"));
    }

    @Test
    void informaTodasLasReglasQueFallan() {
        String mensaje = mensajeDe("abc");

        assertTrue(mensaje.contains("12 caracteres"));
        assertTrue(mensaje.contains("mayuscula"));
        assertTrue(mensaje.contains("numero"));
        assertTrue(mensaje.contains("especial"));
    }

    @Test
    void validateChangeRechazaLaMismaContrasenaActual() {
        String hashActual = encoder.encode(VALIDA);

        WeakPasswordException e = assertThrows(WeakPasswordException.class,
                () -> policy.validateChange(VALIDA, hashActual));

        assertTrue(e.getMessage().contains("diferente"));
    }

    @Test
    void validateChangeAceptaUnaContrasenaDistinta() {
        String hashActual = encoder.encode(VALIDA);

        assertDoesNotThrow(() -> policy.validateChange("Otra#Clave2027x", hashActual));
    }

    @Test
    void validateChangeSinHashActualSoloValidaLasReglas() {
        assertDoesNotThrow(() -> policy.validateChange(VALIDA, null));
        assertThrows(WeakPasswordException.class, () -> policy.validateChange("corta", null));
    }

    @Test
    void validateChangeAplicaPrimeroLasReglasDeComposicion() {
        String hashActual = encoder.encode("debil");

        assertThrows(WeakPasswordException.class, () -> policy.validateChange("debil", hashActual));
    }
}