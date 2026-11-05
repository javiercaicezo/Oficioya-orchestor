package eci.edu.dosw.local;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocalNotificationServiceTest {

    private final LocalNotificationService service = new LocalNotificationService();

    @Test
    void registraElCodigoDeRecuperacion() {
        service.sendPasswordResetCode("a@x.com", "123456", 15);

        LocalNotificationService.SentMessage mensaje = service.sentMessages().get(0);
        assertEquals("RESET_CODE", mensaje.type());
        assertEquals("a@x.com", mensaje.email());
        assertEquals("123456", mensaje.code());
    }

    @Test
    void registraElAvisoDeCambioDeContrasena() {
        service.sendPasswordChangedNotice("a@x.com");

        LocalNotificationService.SentMessage mensaje = service.sentMessages().get(0);
        assertEquals("PASSWORD_CHANGED", mensaje.type());
        assertNull(mensaje.code());
    }

    @Test
    void clearVaciaLosMensajes() {
        service.sendPasswordChangedNotice("a@x.com");

        service.clear();

        assertTrue(service.sentMessages().isEmpty());
    }
}
