package eci.edu.dosw.user;

import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.identity.service.JwtProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.util.Optional;
import java.util.UUID;

/**
 * Cliente HTTP hacia el microservicio de Usuarios para operaciones internas con
 * rol SERVICE.
 */
@Service
@Primary
@Profile("!test")
public class HttpUserService implements UserService {

    private static final Logger log = LoggerFactory.getLogger(HttpUserService.class);

    private final RestClient restClient;
    private final JwtProvider jwtProvider;

    public HttpUserService(
            @Value("${users.service.url:http://localhost:8080}") String usersServiceUrl,
            JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
        this.restClient = RestClient.builder()
                .baseUrl(usersServiceUrl)
                .build();
    }

    @Override
    public Optional<UserDto> findById(UUID id) {
        try {
            UserDto user = restClient.get()
                    .uri("/api/v1/users/{id}/account", id)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtProvider.generateServiceToken())
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .body(UserDto.class);
            return Optional.ofNullable(user);
        } catch (HttpClientErrorException.NotFound e) {
            return Optional.empty();
        } catch (Exception e) {
            log.error("Error al consultar usuario por id {}: {}", id, e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public Optional<UserDto> findByEmail(String email) {
        try {
            UserDto user = restClient.get()
                    .uri(uriBuilder -> uriBuilder
                            .path("/api/v1/users/by-email")
                            .queryParam("email", email)
                            .build())
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtProvider.generateServiceToken())
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .body(UserDto.class);
            return Optional.ofNullable(user);
        } catch (HttpClientErrorException.NotFound e) {
            return Optional.empty();
        } catch (Exception e) {
            log.warn("Usuario con email {} no encontrado o error en Users: {}", email, e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public UserDto createProfile(NewUser newUser) {
        try {
            return restClient.post()
                    .uri("/api/v1/users")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtProvider.generateServiceToken())
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(newUser)
                    .retrieve()
                    .onStatus(HttpStatusCode::is4xxClientError, (req, resp) -> {
                        if (resp.getStatusCode().value() == 409) {
                            throw new DuplicateUserException();
                        }
                        throw new HttpClientErrorException(resp.getStatusCode(), resp.getStatusText());
                    })
                    .body(UserDto.class);
        } catch (DuplicateUserException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error al crear perfil en Users: {}", e.getMessage());
            throw new RuntimeException("Error al comunicarse con el microservicio de usuarios: " + e.getMessage(), e);
        }
    }

    @Override
    public void deleteProfile(UUID id) {
        try {
            restClient.delete()
                    .uri("/api/v1/users/{id}", id)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtProvider.generateServiceToken())
                    .retrieve()
                    .toBodilessEntity();
            log.info("Compensación exitosa: perfil con id {} eliminado en Users", id);
        } catch (Exception e) {
            log.error("Fallo al compensar eliminación de perfil {} en Users: {}", id, e.getMessage());
        }
    }
}
