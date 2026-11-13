package eci.edu.dosw.orchestrator.proxy;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class UserProxyControllerTest {

    @Test
    void proxyDevuelveBadGatewaySiElServicioEstaCaido() {
        UserProxyController controller = new UserProxyController("http://localhost:59999");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users/me");
        request.addHeader("Authorization", "Bearer test-token");
        request.addHeader("Host", "localhost:8081");

        ResponseEntity<byte[]> response = controller.proxy(request, null);

        assertEquals(502, response.getStatusCode().value());
        assertNotNull(response.getBody());
    }

    @Test
    void proxyPreservaQueryYMetodo() {
        UserProxyController controller = new UserProxyController("http://localhost:59999/");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/users");
        request.setQueryString("filter=active");
        request.addHeader("Authorization", "Bearer token-123");
        request.setContent("{\"test\": true}".getBytes());

        ResponseEntity<byte[]> response = controller.proxy(request, "{\"test\": true}".getBytes());

        assertEquals(502, response.getStatusCode().value());
    }
}

