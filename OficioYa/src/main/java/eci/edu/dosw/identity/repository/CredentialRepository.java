package eci.edu.dosw.identity.repository;

import eci.edu.dosw.identity.model.Credential;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Spring Data JPA Repository for the {@link Credential} entity.
 * Provides abstracted database access and auto-generated SQL queries.
 * 
 * Includes custom derived queries to locate credentials via the logical 
 * {@code userId} and compensation methods to support distributed transaction 
 * rollbacks during the user registration workflow.
 */
import java.util.Optional;

public interface CredentialRepository extends JpaRepository<Credential, Long> {

    Optional<Credential> findByUserId(Long userId);

    boolean existsByUserId(Long userId);

    /** Devuelve cuantas filas borro (0 o 1). Se usa como compensacion si falla un registro. */
    long deleteByUserId(Long userId);
}
