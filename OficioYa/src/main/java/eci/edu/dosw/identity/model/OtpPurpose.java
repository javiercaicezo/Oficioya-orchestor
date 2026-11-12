package eci.edu.dosw.identity.model;

/**
 * Defines the allowed use cases for a One-Time Password (OTP).
 * Stored as a strict string value in the database to ensure data integrity
 * and prevent typos across the authentication orchestrator.
 */
public enum OtpPurpose {
    RESET_PASSWORD
}
