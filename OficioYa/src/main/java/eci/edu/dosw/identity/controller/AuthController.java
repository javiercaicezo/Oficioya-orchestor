package eci.edu.dosw.identity.controller;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;
import eci.edu.dosw.orchestrator.AuthOrchestrator;
import eci.edu.dosw.orchestrator.dto.ChangePasswordRequest;
import eci.edu.dosw.orchestrator.dto.ForgotPasswordRequest;
import eci.edu.dosw.orchestrator.dto.LoginRequest;
import eci.edu.dosw.orchestrator.dto.LoginResponse;
import eci.edu.dosw.orchestrator.dto.RegisterRequest;
import eci.edu.dosw.orchestrator.dto.ResetPasswordRequest;
import eci.edu.dosw.user.UserDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;


/**
 * REST API Controller for Identity and Authentication in the OficioYa platform.
 * Acts as a Facade and delegates business logic to the {@link AuthOrchestrator}.
 * Responsible for payload validation, security context extraction, and fulfilling
 * requirements RF-01 to RF-05 and RNF-06.
 */
import java.util.UUID;

@Tag(name = "Autenticación", description = "Operaciones de autenticación, registro y gestión de credenciales (RF-01 a RF-05, RNF-06)")
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthOrchestrator authOrchestrator;


    public AuthController(AuthOrchestrator authOrchestrator) {
        this.authOrchestrator = authOrchestrator;
    }

    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Autenticación exitosa, token JWT generado"),
        @ApiResponse(responseCode = "401", description = "Credenciales inválidas o usuario inactivo",
                     content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
        @ApiResponse(responseCode = "423", description = "Cuenta bloqueada temporalmente por intentos fallidos",
                     content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/login")

    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        return authOrchestrator.login(request);
    }

    @Operation(summary = "Registrar nuevo usuario", description = "Registra un usuario en User Domain y crea su credencial en Identity Domain.")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "Usuario registrado exitosamente"),
        @ApiResponse(responseCode = "400", description = "Contraseña débil según política de seguridad",
                     content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
        @ApiResponse(responseCode = "403", description = "Rol prohibido para autorregistro (ej. ADMIN)",
                     content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
        @ApiResponse(responseCode = "409", description = "Correo electrónico ya registrado",
                     content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("/register")

    public UserDto register(@Valid @RequestBody RegisterRequest register) {
        return authOrchestrator.register(register);
    }

    @Operation(summary = "Cambiar contraseña de usuario autenticado", description = "Permite cambiar la contraseña validando la contraseña actual.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Contraseña cambiada exitosamente"),
        @ApiResponse(responseCode = "400", description = "Nueva contraseña débil o igual a la actual",
                     content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
        @ApiResponse(responseCode = "401", description = "Contraseña actual incorrecta",
                     content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PutMapping("/change")
    public void changePassword(Authentication authentication, @Valid @RequestBody ChangePasswordRequest request) {
        Object principal = authentication.getPrincipal();
        UUID userId = principal instanceof UUID uuid ? uuid : UUID.fromString(String.valueOf(principal));
        authOrchestrator.changePassword(userId, request);
    }

    @Operation(summary = "Solicitar recuperación de contraseña (olvido)", description = "Genera y envía un código OTP por correo si la cuenta existe.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Solicitud procesada (respuesta genérica)"),
        @ApiResponse(responseCode = "429", description = "Límite de solicitudes de código excedido",
                     content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/forgot")

    public void forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authOrchestrator.forgotPassword(request);
    }

    @Operation(summary = "Restablecer contraseña con código OTP", description = "Valida el código OTP y actualiza la contraseña.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Contraseña restablecida exitosamente"),
        @ApiResponse(responseCode = "400", description = "Código OTP inválido/expirado o contraseña débil",
                     content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/reset")

    public void resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authOrchestrator.resetPassword(request);
    }
}
