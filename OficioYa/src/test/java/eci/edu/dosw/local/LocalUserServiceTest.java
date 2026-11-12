package eci.edu.dosw.local;

import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.user.NewUser;
import eci.edu.dosw.user.Role;
import eci.edu.dosw.user.UserDto;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocalUserServiceTest {

    private final LocalUserService service = new LocalUserService();

    private NewUser nuevo(String email) {
        return new NewUser("Ana", email, Set.of(Role.CONTRATANTE));
    }

    @Test
    void asignaIdsConsecutivosYUsuarioActivo() {
        UserDto a = service.createProfile(nuevo("a@x.com"));
        UserDto b = service.createProfile(nuevo("b@x.com"));

        assertEquals(1L, a.id());
        assertEquals(2L, b.id());
        assertTrue(a.active());
    }

    @Test
    void encuentraPorId() {
        UserDto creado = service.createProfile(nuevo("a@x.com"));

        assertEquals(creado, service.findById(creado.id()).orElseThrow());
        assertTrue(service.findById(99L).isEmpty());
    }

    @Test
    void buscaPorCorreoSinImportarMayusculasNiEspacios() {
        UserDto creado = service.createProfile(nuevo("Ana@Correo.com"));

        assertEquals(creado, service.findByEmail("  ana@correo.COM ").orElseThrow());
    }

    @Test
    void correoInexistenteONuloDaVacio() {
        assertTrue(service.findByEmail("nadie@x.com").isEmpty());
        assertTrue(service.findByEmail(null).isEmpty());
    }

    @Test
    void rechazaUnCorreoRepetido() {
        service.createProfile(nuevo("a@x.com"));

        assertThrows(DuplicateUserException.class, () -> service.createProfile(nuevo("A@X.com")));
    }

    @Test
    void deactivateMarcaAlUsuarioComoInactivo() {
        UserDto creado = service.createProfile(nuevo("a@x.com"));

        service.deactivate(creado.id());

        assertFalse(service.findById(creado.id()).orElseThrow().active());
    }

    @Test
    void clearVaciaTodoYReiniciaLosIds() {
        service.createProfile(nuevo("a@x.com"));

        service.clear();

        assertTrue(service.findByEmail("a@x.com").isEmpty());
        assertEquals(1L, service.createProfile(nuevo("b@x.com")).id());
    }

    @Test
    void deleteProfileBorraAlUsuario() {
        UserDto creado = service.createProfile(nuevo("a@x.com"));

        service.deleteProfile(creado.id());

        assertTrue(service.findById(creado.id()).isEmpty());
        assertTrue(service.findByEmail("a@x.com").isEmpty());
    }
}
