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
import java.util.UUID;

/**
 * Service managing One-Time Password (OTP) tokens for password recovery workflows.
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
     */
    @Transactional
    public String generate(UUID userId) {
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
     */
    @Transactional(noRollbackFor = InvalidOtpException.class)
    public void verifyAndConsume(UUID userId, String code) {
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

    private boolean matches(Otp otp, UUID userId, String code) {
        byte[] esperado = otp.getCodeHash().getBytes(StandardCharsets.UTF_8);
        byte[] recibido = hash(userId, code).getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(esperado, recibido);
    }

    private String hash(UUID userId, String code) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] digest = sha256.digest((userId + ":" + code).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 no disponible", e);
        }
    }

    private LocalDateTime now() {
        return LocalDateTime.now(clock);
    }
}
