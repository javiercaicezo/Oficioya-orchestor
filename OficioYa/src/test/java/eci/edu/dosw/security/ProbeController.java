package eci.edu.dosw.security;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProbeController {

    @GetMapping({ "/api/probe", "/api/admin/probe", "/api/worker/probe",
            "/api/v1/admin/probe", "/api/v1/worker/probe" })
    public String probe(Authentication authentication) {
        return String.valueOf(authentication.getPrincipal());
    }
}
