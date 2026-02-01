package io.mzaslav.pqc.exception;

/**
 * Base exception for all PQC-related errors.
 * <p>
 * This exception hierarchy provides detailed error information
 * for cryptographic operations including key generation, 
 * encapsulation, encryption, and digital signatures.
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public class PqcException extends RuntimeException {

    /**
     * Constructs a new PQC exception with the specified message.
     *
     * @param message the detail message
     */
    public PqcException(String message) {
        super(message);
    }

    /**
     * Constructs a new PQC exception with the specified message and cause.
     *
     * @param message the detail message
     * @param cause   the cause of this exception
     */
    public PqcException(String message, Throwable cause) {
        super(message, cause);
    }
}
