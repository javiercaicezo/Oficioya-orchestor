package eci.edu.dosw.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Cross-Origin Resource Sharing (CORS) configuration for the application.
 * Enables the frontend application (e.g., Vite dev server on localhost:5173 and preview on localhost:4173)
 * to interact with the backend API running on port 8080.
 */
@Configuration
public class CorsConfig {

    @Value("${cors.allowed-origins:http://localhost:5173,http://localhost:4173}")
    private List<String> allowedOrigins;

    /**
     * Configures and registers global CORS policies for all incoming HTTP request paths.
   
     * Settings include:

     * Allowed Origins: Local frontend clients ({@code http://localhost:5173}, {@code http://localhost:4173}).
     * Allowed HTTP Methods: {@code GET}, {@code POST}, {@code PUT}, {@code PATCH}, {@code DELETE}, {@code OPTIONS}.
     * Allowed Headers: Wildcard ({@code *}) to accept standard and custom authorization headers.</li>
     * Credentials: Enabled ({@code true}) to allow cookies and {@code Authorization} headers in cross-origin requests.
     * Max Age: 3600 seconds (1 hour) pre-flight cache duration.
     * 
     *
     * @return A configured {@link CorsConfigurationSource} applied to all routes ({@code /**}).
     */
     @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(allowedOrigins);

        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));

        config.setAllowedHeaders(List.of("*"));

        // Necesario para que el browser envíe las cookies / Authorization header
        config.setAllowCredentials(true);

        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}

