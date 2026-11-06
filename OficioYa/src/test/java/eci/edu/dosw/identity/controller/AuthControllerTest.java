package eci.edu.dosw.identity.controller;

import eci.edu.dosw.identity.exception.AccountLockedException;
import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.identity.exception.ForbiddenRoleException;
import eci.edu.dosw.identity.exception.InvalidCredentialsException;
import eci.edu.dosw.identity.exception.InvalidOtpException;
import eci.edu.dosw.identity.exception.OtpRateLimitException;
import eci.edu.dosw.identity.exception.WeakPasswordException;
import eci.edu.dosw.orchestrator.AuthOrchestrator;
import eci.edu.dosw.orchestrator.dto.ChangePasswordRequest;
import eci.edu.dosw.orchestrator.dto.ForgotPasswordRequest;
import eci.edu.dosw.orchestrator.dto.LoginRequest;
import eci.edu.dosw.orchestrator.dto.LoginResponse;
import eci.edu.dosw.orchestrator.dto.RegisterRequest;
import eci.edu.dosw.orchestrator.dto.ResetPasswordRequest;
import eci.edu.dosw.user.Role;
import eci.edu.dosw.user.UserDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Set;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DisplayName("Pruebas del AuthController y GlobalExceptionHandler")
class AuthControllerTest {

    private MockMvc mockMvc;
    private AuthOrchestrator authOrchestrator;

    @BeforeEach
    void setUp() {
        authOrchestrator = mock(AuthOrchestrator.class);
        AuthController controller = new AuthController(authOrchestrator);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Nested
    @DisplayName("Endpoint POST /api/v1/auth/login")
    class LoginTests {

        @Test
        @DisplayName("200 OK cuando las credenciales son correctas")
        void loginExitoso() throws Exception {
            when(authOrchestrator.login(any(LoginRequest.class)))
                    .thenReturn(new LoginResponse("jwt-token-valido", 1800, 1L, Set.of(Role.CLIENT)));

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "email": "ana@x.com",
                                      "password": "Password123#"
                                    }
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.token", is("jwt-token-valido")))
                    .andExpect(jsonPath("$.expiresInSeconds", is(1800)))
                    .andExpect(jsonPath("$.userId", is(1)));
        }

        @Test
        @DisplayName("401 UNAUTHORIZED con mensaje generico que no revela si la cuenta existe")
        void loginCredencialesInvalidas() throws Exception {
            when(authOrchestrator.login(any(LoginRequest.class)))
                    .thenThrow(new InvalidCredentialsException());

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "email": "inexistente@x.com",
                                      "password": "Password123#"
                                    }
                                    """))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.message", is("Usuario o contraseña incorrectos, por favor rectifique sus credenciales.")));
        }

        @Test
        @DisplayName("423 LOCKED cuando la cuenta esta temporalmente bloqueada")
        void loginCuentaBloqueada() throws Exception {
            when(authOrchestrator.login(any(LoginRequest.class)))
                    .thenThrow(new AccountLockedException());

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "email": "bloqueado@x.com",
                                      "password": "Password123#"
                                    }
                                    """))
                    .andExpect(status().isLocked())
                    .andExpect(jsonPath("$.message", containsString("bloqueada")));
        }

        @Test
        @DisplayName("400 BAD_REQUEST cuando los campos requeridos no son validos")
        void loginCamposInvalidos() throws Exception {
            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "email": "no-es-correo",
                                      "password": ""
                                    }
                                    """))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Endpoint POST /api/v1/auth/register")
    class RegisterTests {

        @Test
        @DisplayName("200 OK al registrar exitosamente")
        void registerExitoso() throws Exception {
            UserDto nuevo = new UserDto(1L, "Carlos", "carlos@x.com", Set.of(Role.CLIENT), true);
            when(authOrchestrator.register(any(RegisterRequest.class))).thenReturn(nuevo);

            mockMvc.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "name": "Carlos",
                                      "email": "carlos@x.com",
                                      "password": "Password123#",
                                      "roles": ["CLIENT"]
                                    }
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is(1)))
                    .andExpect(jsonPath("$.email", is("carlos@x.com")));
        }

        @Test
        @DisplayName("403 FORBIDDEN si intenta registrarse con rol ADMINISTRATOR")
        void registerRolProhibido() throws Exception {
            when(authOrchestrator.register(any(RegisterRequest.class)))
                    .thenThrow(new ForbiddenRoleException());

            mockMvc.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "name": "Carlos",
                                      "email": "carlos@x.com",
                                      "password": "Password123#",
                                      "roles": ["ADMINISTRATOR"]
                                    }
                                    """))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.message", containsString("ADMINISTRATOR")));
        }

        @Test
        @DisplayName("409 CONFLICT si el correo ya esta registrado")
        void registerCorreoDuplicado() throws Exception {
            when(authOrchestrator.register(any(RegisterRequest.class)))
                    .thenThrow(new DuplicateUserException());

            mockMvc.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "name": "Carlos",
                                      "email": "duplicado@x.com",
                                      "password": "Password123#",
                                      "roles": ["CLIENT"]
                                    }
                                    """))
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.message", containsString("Ya existe un usuario")));
        }

        @Test
        @DisplayName("400 BAD_REQUEST si la contrasena es debil")
        void registerContrasenaDebil() throws Exception {
            when(authOrchestrator.register(any(RegisterRequest.class)))
                    .thenThrow(new WeakPasswordException());

            mockMvc.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "name": "Carlos",
                                      "email": "carlos@x.com",
                                      "password": "123",
                                      "roles": ["CLIENT"]
                                    }
                                    """))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message", containsString("politica de seguridad")));
        }
    }

    @Nested
    @DisplayName("Endpoint PUT /api/v1/auth/change")
    class ChangePasswordTests {

        @Test
        @DisplayName("200 OK al cambiar contrasena correctamente")
        void changePasswordExitoso() throws Exception {
            doNothing().when(authOrchestrator).changePassword(eq(1L), any(ChangePasswordRequest.class));

            mockMvc.perform(put("/api/v1/auth/change")
                            .param("userId", "1")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "currentPassword": "Password123#",
                                      "newPassword": "NuevaPassword123#"
                                    }
                                    """))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("401 UNAUTHORIZED si la contrasena actual es incorrecta")
        void changePasswordActualIncorrecta() throws Exception {
            doThrow(new InvalidCredentialsException())
                    .when(authOrchestrator).changePassword(eq(1L), any(ChangePasswordRequest.class));

            mockMvc.perform(put("/api/v1/auth/change")
                            .param("userId", "1")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "currentPassword": "ClaveErronea123#",
                                      "newPassword": "NuevaPassword123#"
                                    }
                                    """))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("400 BAD_REQUEST si la nueva contrasena no cumple la politica")
        void changePasswordNuevaDebil() throws Exception {
            doThrow(new WeakPasswordException())
                    .when(authOrchestrator).changePassword(eq(1L), any(ChangePasswordRequest.class));

            mockMvc.perform(put("/api/v1/auth/change")
                            .param("userId", "1")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "currentPassword": "Password123#",
                                      "newPassword": "debil"
                                    }
                                    """))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message", containsString("politica de seguridad")));
        }
    }

    @Nested
    @DisplayName("Endpoint POST /api/v1/auth/forgot")
    class ForgotPasswordTests {

        @Test
        @DisplayName("200 OK tanto si el correo existe como si no existe (no revela informacion)")
        void forgotPasswordExitoso() throws Exception {
            doNothing().when(authOrchestrator).forgotPassword(any(ForgotPasswordRequest.class));

            mockMvc.perform(post("/api/v1/auth/forgot")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "email": "alguien@x.com"
                                    }
                                    """))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("429 TOO_MANY_REQUESTS cuando se excede el limite de solicitudes de OTP")
        void forgotPasswordLimiteSuperado() throws Exception {
            doThrow(new OtpRateLimitException())
                    .when(authOrchestrator).forgotPassword(any(ForgotPasswordRequest.class));

            mockMvc.perform(post("/api/v1/auth/forgot")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "email": "alguien@x.com"
                                    }
                                    """))
                    .andExpect(status().isTooManyRequests())
                    .andExpect(jsonPath("$.message", containsString("limite de solicitudes")));
        }
    }

    @Nested
    @DisplayName("Endpoint POST /api/v1/auth/reset")
    class ResetPasswordTests {

        @Test
        @DisplayName("200 OK al restablecer contrasena con codigo valido")
        void resetPasswordExitoso() throws Exception {
            doNothing().when(authOrchestrator).resetPassword(any(ResetPasswordRequest.class));

            mockMvc.perform(post("/api/v1/auth/reset")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "email": "ana@x.com",
                                      "code": "123456",
                                      "newPassword": "NuevaPassword123#"
                                    }
                                    """))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("400 BAD_REQUEST si el codigo OTP es invalido o expiro")
        void resetPasswordCodigoInvalido() throws Exception {
            doThrow(new InvalidOtpException())
                    .when(authOrchestrator).resetPassword(any(ResetPasswordRequest.class));

            mockMvc.perform(post("/api/v1/auth/reset")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "email": "ana@x.com",
                                      "code": "999999",
                                      "newPassword": "NuevaPassword123#"
                                    }
                                    """))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message", containsString("invalido o ha expirado")));
        }

        @Test
        @DisplayName("400 BAD_REQUEST si la nueva contrasena es debil")
        void resetPasswordContrasenaDebil() throws Exception {
            doThrow(new WeakPasswordException())
                    .when(authOrchestrator).resetPassword(any(ResetPasswordRequest.class));

            mockMvc.perform(post("/api/v1/auth/reset")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "email": "ana@x.com",
                                      "code": "123456",
                                      "newPassword": "123"
                                    }
                                    """))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message", containsString("politica de seguridad")));
        }
    }
}

