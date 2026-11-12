package eci.edu.dosw.identity.repository;

import eci.edu.dosw.identity.model.Credential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA Repository for the {@link Credential} entity.
 * Provides abstracted database access and auto-generated SQL queries.
 */
public interface CredentialRepository extends JpaRepository<Credential, UUID> {

    Optional<Credential> findByUserId(UUID userId);

    Optional<Credential> findByEmail(String email);

    boolean existsByUserId(UUID userId);

    boolean existsByEmail(String email);

    /** Devuelve cuántas filas borró (0 o 1). Se usa como compensación si falla un registro. */
    long deleteByUserId(UUID userId);
}
