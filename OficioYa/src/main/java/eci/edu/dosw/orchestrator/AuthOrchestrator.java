package eci.edu.dosw.orchestrator;

import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.identity.exception.ForbiddenRoleException;
import eci.edu.dosw.identity.exception.InvalidCredentialsException;
import eci.edu.dosw.identity.service.CredentialService;
import eci.edu.dosw.identity.service.JwtProvider;
import eci.edu.dosw.identity.service.PasswordPolicyService;
import eci.edu.dosw.orchestrator.dto.LoginRequest;
import eci.edu.dosw.orchestrator.dto.LoginResponse;
import eci.edu.dosw.orchestrator.dto.RegisterRequest;
import eci.edu.dosw.user.NewUser;
import eci.edu.dosw.user.Role;
import eci.edu.dosw.user.UserDto;
import eci.edu.dosw.user.UserService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;

/**
 * Coordina los flujos de autenticacion entre los modulos User e Identity (OR-01
 * a OR-03).
 * Es el unico que conoce a ambos; los modulos no se llaman entre si.
 */
@Service
public class AuthOrchestrator {

    private final UserService userService;
    private final CredentialService credentialService;
    private final PasswordPolicyService passwordPolicy;
    private final JwtProvider jwtProvider;

    public AuthOrchestrator(UserService userService,
            CredentialService credentialService,
            PasswordPolicyService passwordPolicy,
            JwtProvider jwtProvider) {
        this.userService = userService;
        this.credentialService = credentialService;
        this.passwordPolicy = passwordPolicy;
        this.jwtProvider = jwtProvider;
    }

    /**
     * Login: busca el perfil en User, rechaza si no existe o esta inactivo,
     * verifica la contrasena
     * en Identity y emite el JWT. Todos los rechazos usan el mismo mensaje generico
     * (RF-02, RNF-07).
     */
    public LoginResponse login(LoginRequest request) {
        UserDto user = userService.findByEmail(request.email())
                .orElseThrow(InvalidCredentialsException::new);
        if (!user.active()) {
            throw new InvalidCredentialsException();
        }

        credentialService.authenticate(user.id(), request.password());

        String token = jwtProvider.generateToken(user.id(), nombresDeRoles(user.roles()));
        return new LoginResponse(token, jwtProvider.getExpirationSeconds(), user.id(), user.roles());
    }

    /**
     * Registro: valida todo lo que pueda fallar ANTES de crear nada, crea el perfil
     * en User y luego la
     * credencial en Identity. Si la credencial falla, se compensa borrando el
     * perfil (OR-02).
     */
    public UserDto register(RegisterRequest request) {
        if (request.roles() != null && request.roles().contains(Role.ADMINISTRATOR)) {
            throw new ForbiddenRoleException();
        }
        passwordPolicy.validate(request.password());
        if (userService.findByEmail(request.email()).isPresent()) {
            throw new DuplicateUserException();
        }

        UserDto creado = userService.createProfile(
                new NewUser(request.name(), request.email(), request.roles()));
        try {
            credentialService.create(creado.id(), request.password());
        } catch (RuntimeException e) {
            deshacerPerfil(creado.id(), e);
            throw e;
        }
        return creado;
    }

    private void deshacerPerfil(Long userId, RuntimeException causa) {
        try {
            userService.deleteProfile(userId);
        } catch (RuntimeException falloAlDeshacer) {
            causa.addSuppressed(falloAlDeshacer);
        }
    }

    private List<String> nombresDeRoles(Set<Role> roles) {
        return roles.stream().map(Role::name).sorted().toList();
    }
}