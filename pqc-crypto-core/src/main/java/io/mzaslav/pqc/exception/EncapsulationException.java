package io.mzaslav.pqc.exception;

/**
 * Exception thrown when key encapsulation/decapsulation fails.
 * <p>
 * KEM (Key Encapsulation Mechanism) errors include:
 * <ul>
 *   <li>Invalid public key format</li>
 *   <li>Encapsulation algorithm failure</li>
 *   <li>Decapsulation failure (invalid ciphertext)</li>
 * </ul>
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public class EncapsulationException extends PqcException {

    public EncapsulationException(String message) {
        super(message);
    }

    public EncapsulationException(String message, Throwable cause) {
        super(message, cause);
    }
}
