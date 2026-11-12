package eci.edu.dosw.identity.repository;

import eci.edu.dosw.identity.model.Otp;
import eci.edu.dosw.identity.model.OtpPurpose;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Spring Data JPA Repository for the {@link Otp} entity.
 * Handles the persistence lifecycle of One-Time Passwords.
 * 
 * Key Responsibilities:
 *   Retrieval of valid, unexpired OTPs via complex derived queries
 *   Fraud prevention by tracking OTP issuance rates (Rate Limiting).
 *   State invalidation via explicit JPQL updates to ensure only one 
 *       OTP remains active per user and purpose.
 */

public interface OtpRepository extends JpaRepository<Otp, Long> {

    Optional<Otp> findFirstByUserIdAndPurposeAndUsedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
            Long userId, OtpPurpose purpose, LocalDateTime now);

    /** OTP vigente mas reciente: no usado y no vencido. */
    default Optional<Otp> findActive(Long userId, OtpPurpose purpose, LocalDateTime now) {
        return findFirstByUserIdAndPurposeAndUsedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
                userId, purpose, now);
    }

    /** Cuenta los OTP creados despues de una fecha (limite de 3 solicitudes por hora). */
    long countByUserIdAndPurposeAndCreatedAtAfter(Long userId, OtpPurpose purpose, LocalDateTime since);

    /** Marca como usados todos los OTP vigentes del usuario para ese proposito. */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update Otp o set o.used = true "
            + "where o.userId = :userId and o.purpose = :purpose and o.used = false")
    int invalidateActive(@Param("userId") Long userId, @Param("purpose") OtpPurpose purpose);
}
