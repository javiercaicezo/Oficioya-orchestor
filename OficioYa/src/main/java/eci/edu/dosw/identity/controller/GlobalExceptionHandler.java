package eci.edu.dosw.identity.controller;

import eci.edu.dosw.identity.exception.AccountInactiveException;
import eci.edu.dosw.identity.exception.AccountLockedException;
import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.identity.exception.ForbiddenRoleException;
import eci.edu.dosw.identity.exception.InvalidCredentialsException;
import eci.edu.dosw.identity.exception.InvalidOtpException;
import eci.edu.dosw.identity.exception.OtpRateLimitException;
import eci.edu.dosw.identity.exception.UserNotFoundException;
import eci.edu.dosw.identity.exception.UsersServiceUnavailableException;
import eci.edu.dosw.identity.exception.WeakPasswordException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

/**
 * Global exception handler (Controller Advice) for the Identity module.
 * Intercepts domain-specific exceptions and translates them into standardized HTTP 
 * responses using the {@link ErrorResponse} DTO. It centralizes error management, 
 * prevents raw stack traces from reaching the client, and ensures compliance with 
 * RESTful HTTP status codes (e.g., 401, 403, 409) as defined in the API contracts.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleInvalidCredentials(InvalidCredentialsException ex) {
        log.warn("Excepción de seguridad: credenciales inválidas o usuario inactivo");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ErrorResponse> handleAccountLocked(AccountLockedException ex) {
        log.warn("Excepción de seguridad: cuenta bloqueada");
        return ResponseEntity.status(HttpStatus.LOCKED)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(WeakPasswordException.class)
    public ResponseEntity<ErrorResponse> handleWeakPassword(WeakPasswordException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(InvalidOtpException.class)
    public ResponseEntity<ErrorResponse> handleInvalidOtp(InvalidOtpException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(OtpRateLimitException.class)
    public ResponseEntity<ErrorResponse> handleOtpRateLimit(OtpRateLimitException ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(DuplicateUserException.class)
    public ResponseEntity<ErrorResponse> handleDuplicateUser(DuplicateUserException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(ForbiddenRoleException.class)
    public ResponseEntity<ErrorResponse> handleForbiddenRole(ForbiddenRoleException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUserNotFound(UserNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(AccountInactiveException.class)
    public ResponseEntity<ErrorResponse> handleAccountInactive(AccountInactiveException ex) {
        log.warn("Excepción de seguridad: cuenta inactiva o bloqueada");
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(UsersServiceUnavailableException.class)
    public ResponseEntity<ErrorResponse> handleUsersServiceUnavailable(UsersServiceUnavailableException ex) {
        log.error("Microservicio de usuarios no disponible: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
        String msg = ex.getBindingResult().getFieldErrors().stream()
                .map(err -> err.getField() + ": " + err.getDefaultMessage())
                .collect(Collectors.joining(", "));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(msg.isEmpty() ? "Solicitud invalida" : msg));
    }
}
