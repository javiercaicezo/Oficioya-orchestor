package eci.edu.dosw.identity.controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import eci.edu.dosw.orchestrator.AuthOrchestrator;
import eci.edu.dosw.orchestrator.dto.*;
import eci.edu.dosw.user.UserDto;
import jakarta.validation.Valid;

@RestController 
@RequestMapping("/api/v1/auth")
public class AuthController {
    

    private final AuthOrchestrator authOrchestrator; 

    public AuthController(AuthOrchestrator authOrchestrator){
        this.authOrchestrator = authOrchestrator;
    }


    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request){
        return authOrchestrator.login(request);
    }

    @PostMapping("/register")
    public UserDto register(@Valid @RequestBody RegisterRequest register){
        return authOrchestrator.register(register);
    }

    @PutMapping("/change")
    public void changePassword(@RequestParam Long userId, @Valid @RequestBody ChangePasswordRequest request){
        authOrchestrator.changePassword(userId, request);
    }

    @PostMapping("/forgot")
    public void forgotPassword(@Valid @RequestBody ForgotPasswordRequest request){
        authOrchestrator.forgotPassword(request);
    }

    @PostMapping("/reset")
    public void resetPassword(@Valid @RequestBody ResetPasswordRequest request){
        authOrchestrator.resetPassword(request);
    }
}
