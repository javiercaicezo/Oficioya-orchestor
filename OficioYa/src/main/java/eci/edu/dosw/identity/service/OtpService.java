package eci.edu.dosw.identity.service;

import eci.edu.dosw.identity.exception.InvalidOtpException;
import eci.edu.dosw.identity.exception.OtpRateLimitException;
import eci.edu.dosw.identity.exception.UserNotFoundException;
import eci.edu.dosw.identity.model.Otp;
import eci.edu.dosw.identity.model.OtpPurpose;
import eci.edu.dosw.identity.repository.CredentialRepository;
import eci.edu.dosw.identity.repository.OtpRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.HexFormat;

/**
 * Service managing One-Time Password (OTP) tokens for password recovery workflows.
 * Enforces security constraints including:
 * <ul>
 *   <li>6-digit pseudo-random numeric tokens generated via {@link SecureRandom}.</li>
 *   <li>15-minute expiration window.</li>
 *   <li>Single-use consumption.</li>
 *   <li>Rate limiting: maximum of 3 generation requests per hour per user.</li>
 *   <li>Brute-force protection: maximum of 5 verification attempts per token.</li>
 *   <li>Zero plaintext storage: only user-salted SHA-256 hashes are persisted.</li>
 * </ul>
 */
@Service
public class OtpService {

    public static final int CODE_DIGITS = 6;
    public static final int VALID_MINUTES = 15;
    public static final int MAX_REQUESTS_PER_HOUR = 3;
    public static final int MAX_ATTEMPTS = 3;

    private static final OtpPurpose PURPOSE = OtpPurpose.RESET_PASSWORD;

    private final OtpRepository otpRepository;
    private final CredentialRepository credentialRepository;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public OtpService(OtpRepository otpRepository, CredentialRepository credentialRepository, Clock clock) {
        this.otpRepository = otpRepository;
        this.credentialRepository = credentialRepository;
        this.clock = clock;
    }

    /**
     * Generates a new OTP code for password recovery, invalidating any previously active OTPs.
     * Enforces rate limiting per hour. Returns the plaintext code to be delivered to the user
     * via notification channels; only the salted SHA-256 hash is persisted in the database.
     *
     * @param userId The unique identifier of the user requesting the OTP.
     * @return The plaintext 6-digit numeric OTP code.
     * @throws UserNotFoundException if no credentials exist for the specified user ID.
     * @throws OtpRateLimitException if the user has exceeded {@value #MAX_REQUESTS_PER_HOUR} requests in the last hour.
     */
    @Transactional
    public String generate(Long userId) {
        if (!credentialRepository.existsByUserId(userId)) {
            throw new UserNotFoundException();
        }
        LocalDateTime now = now();
        long ultimaHora = otpRepository.countByUserIdAndPurposeAndCreatedAtAfter(
                userId, PURPOSE, now.minusHours(1));
        if (ultimaHora >= MAX_REQUESTS_PER_HOUR) {
            throw new OtpRateLimitException();
        }

        otpRepository.invalidateActive(userId, PURPOSE);

        String code = String.format("%0" + CODE_DIGITS + "d", random.nextInt((int) Math.pow(10, CODE_DIGITS)));
        otpRepository.save(new Otp(userId, hash(userId, code), PURPOSE, now, now.plusMinutes(VALID_MINUTES)));
        return code;
    }

    /**
     * Verifies the provided OTP code and marks it as consumed upon success.
     * Increments the failed attempt counter upon mismatch.
     * <p>
     * Security Note: Configured with {@code noRollbackFor = InvalidOtpException.class} to ensure
     * that failed attempts and token invalidation (when reaching {@value #MAX_ATTEMPTS})
     * are committed even though an exception is thrown.
     * </p>
     *
     * @param userId The unique identifier of the user attempting verification.
     * @param code   The plaintext OTP code submitted by the user.
     * @throws InvalidOtpException if no active OTP is found, if the code does not match,
     *                             or if the token has expired/reached max attempts.
     */
    @Transactional(noRollbackFor = InvalidOtpException.class)
    public void verifyAndConsume(Long userId, String code) {
        Otp otp = otpRepository.findActive(userId, PURPOSE, now())
                .orElseThrow(InvalidOtpException::new);

        if (code == null || !matches(otp, userId, code)) {
            otp.setAttempts(otp.getAttempts() + 1);
            if (otp.getAttempts() >= MAX_ATTEMPTS) {
                otp.setUsed(true);
            }
            otpRepository.save(otp);
            throw new InvalidOtpException();
        }

        otp.setUsed(true);
        otpRepository.save(otp);
    }

    /**
     * Compares the expected hash stored in the database with the salted hash of the provided code.
     * Uses constant-time equality check ({@link MessageDigest#isEqual}) to prevent timing attacks.
     *
     * @param otp    The active OTP entity containing the stored hash.
     * @param userId The user ID used as salt.
     * @param code   The plaintext code to verify.
     * @return {@code true} if hashes match; {@code false} otherwise.
     */
    private boolean matches(Otp otp, Long userId, String code) {
        byte[] esperado = otp.getCodeHash().getBytes(StandardCharsets.UTF_8);
        byte[] recibido = hash(userId, code).getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(esperado, recibido);
    }

    /**
     * Computes the hexadecimal SHA-256 digest of the OTP code salted with the user ID:
     * {@code "{userId}:{code}"}.
     *
     * @param userId The user ID acting as the salt.
     * @param code   The plaintext OTP code.
     * @return The 64-character lowercase hex encoded digest.
     * @throws IllegalStateException if SHA-256 algorithm is unexpectedly unavailable.
     */
    private String hash(Long userId, String code) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] digest = sha256.digest((userId + ":" + code).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 no disponible", e);
        }
    }

    /**
     * Returns the current date and time based on the injected {@link Clock}.
     *
     * @return Current {@link LocalDateTime}.
     */
    private LocalDateTime now() {
        return LocalDateTime.now(clock);
    }
}