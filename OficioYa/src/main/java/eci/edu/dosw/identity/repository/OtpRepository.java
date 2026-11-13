package eci.edu.dosw.identity.repository;

import eci.edu.dosw.identity.model.Otp;
import eci.edu.dosw.identity.model.OtpPurpose;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA Repository for the {@link Otp} entity.
 * Handles the persistence lifecycle of One-Time Passwords.
 */
public interface OtpRepository extends JpaRepository<Otp, Long> {

    Optional<Otp> findFirstByUserIdAndPurposeAndUsedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
            UUID userId, OtpPurpose purpose, LocalDateTime now);

    /** OTP vigente más reciente: no usado y no vencido. */
    default Optional<Otp> findActive(UUID userId, OtpPurpose purpose, LocalDateTime now) {
        return findFirstByUserIdAndPurposeAndUsedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
                userId, purpose, now);
    }

    /** Cuenta los OTP creados después de una fecha (límite de 3 solicitudes por hora). */
    long countByUserIdAndPurposeAndCreatedAtAfter(UUID userId, OtpPurpose purpose, LocalDateTime since);

    /** Marca como usados todos los OTP vigentes del usuario para ese propósito. */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update Otp o set o.used = true "
            + "where o.userId = :userId and o.purpose = :purpose and o.used = false")
    int invalidateActive(@Param("userId") UUID userId, @Param("purpose") OtpPurpose purpose);
}
