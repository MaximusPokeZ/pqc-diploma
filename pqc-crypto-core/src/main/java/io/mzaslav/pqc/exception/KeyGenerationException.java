package io.mzaslav.pqc.exception;

/**
 * Exception thrown when key generation fails.
 * <p>
 * This can occur due to:
 * <ul>
 *   <li>Unsupported algorithm or parameter set</li>
 *   <li>Insufficient entropy</li>
 *   <li>JCA provider issues</li>
 * </ul>
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public class KeyGenerationException extends PqcException {

    public KeyGenerationException(String message) {
        super(message);
    }

    public KeyGenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}
