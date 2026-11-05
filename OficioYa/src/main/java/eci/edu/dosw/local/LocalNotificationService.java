package eci.edu.dosw.local;

import eci.edu.dosw.notification.NotificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Implementacion TEMPORAL del modulo Notification: no envia correos, imprime en
 * el log y
 * guarda los mensajes para que las pruebas los consulten. Solo para desarrollo
 * y pruebas.
 */
@Service
@Profile({ "local", "test" })
public class LocalNotificationService implements NotificationService {

    private static final Logger log = LoggerFactory.getLogger(LocalNotificationService.class);

    public record SentMessage(String type, String email, String code) {
    }

    private final List<SentMessage> enviados = new CopyOnWriteArrayList<>();

    @Override
    public void sendPasswordResetCode(String email, String code, int validMinutes) {
        enviados.add(new SentMessage("RESET_CODE", email, code));
        log.info("[LOCAL] Codigo de recuperacion para {}: {} (valido {} min)", email, code, validMinutes);
    }

    @Override
    public void sendPasswordChangedNotice(String email) {
        enviados.add(new SentMessage("PASSWORD_CHANGED", email, null));
        log.info("[LOCAL] Aviso de cambio de contrasena para {}", email);
    }

    /** Solo para pruebas: mensajes "enviados" hasta ahora. */
    public List<SentMessage> sentMessages() {
        return List.copyOf(enviados);
    }

    /** Solo para pruebas. */
    public void clear() {
        enviados.clear();
    }
}
