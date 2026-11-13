package eci.edu.dosw.orchestrator.proxy;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.util.Collections;
import java.util.Enumeration;

/**
 * Controlador Proxy / Gateway en el Orquestador.
 * Reenvía todas las peticiones hacia /api/v1/users/**, /api/v1/admin/** y /api/v1/zones/**
 * al microservicio de Usuarios (${users.service.url}), preservando método HTTP, ruta,
 * query params, payload y cabeceras de autorización.
 */
@RestController
public class UserProxyController {

    private static final Logger log = LoggerFactory.getLogger(UserProxyController.class);

    private final String usersServiceUrl;
    private final RestClient restClient;

    public UserProxyController(@Value("${users.service.url:http://localhost:8080}") String usersServiceUrl) {
        this.usersServiceUrl = usersServiceUrl.replaceAll("/+$", "");
        this.restClient = RestClient.builder().build();
    }

    @RequestMapping(value = {
            "/api/v1/users/**",
            "/api/v1/admin/**",
            "/api/v1/zones/**"
    })
    public ResponseEntity<byte[]> proxy(
            HttpServletRequest request,
            @RequestBody(required = false) byte[] body) {

        String path = request.getRequestURI();
        String query = request.getQueryString();
        String targetUrl = usersServiceUrl + path + (query != null ? "?" + query : "");
        HttpMethod method = HttpMethod.valueOf(request.getMethod());

        log.info("Proxy gateway reenvía: {} {} -> {}", method, path, targetUrl);

        HttpHeaders headers = new HttpHeaders();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames != null && headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            if (name.equalsIgnoreCase(HttpHeaders.HOST) || name.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH)) {
                continue;
            }
            Enumeration<String> values = request.getHeaders(name);
            headers.addAll(name, Collections.list(values));
        }

        try {
            var spec = restClient.method(method)
                    .uri(URI.create(targetUrl))
                    .headers(h -> h.addAll(headers));

            if (body != null && body.length > 0) {
                spec.body(body);
            }

            return spec.exchange((clientRequest, clientResponse) -> {
                HttpHeaders responseHeaders = new HttpHeaders();
                clientResponse.getHeaders().forEach((k, v) -> {
                    if (!k.equalsIgnoreCase(HttpHeaders.TRANSFER_ENCODING)) {
                        responseHeaders.addAll(k, v);
                    }
                });
                byte[] responseBody = clientResponse.getBody().readAllBytes();
                return ResponseEntity.status(clientResponse.getStatusCode())
                        .headers(responseHeaders)
                        .body(responseBody);
            });
        } catch (HttpStatusCodeException ex) {
            return ResponseEntity.status(ex.getStatusCode())
                    .headers(ex.getResponseHeaders())
                    .body(ex.getResponseBodyAsByteArray());
        } catch (Exception ex) {
            log.error("Error en proxy gateway al contactar {}: {}", targetUrl, ex.getMessage());
            return ResponseEntity.status(502).body(("Bad Gateway: " + ex.getMessage()).getBytes());
        }
    }
}

