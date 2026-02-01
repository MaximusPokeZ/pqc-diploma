package io.mzaslav.pqc.exception;

/**
 * Exception thrown when digital signature operations fail.
 * <p>
 * Signature errors include:
 * <ul>
 *   <li>Signature verification failure</li>
 *   <li>Invalid key format</li>
 *   <li>Signing algorithm failure</li>
 * </ul>
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public class SignatureException extends PqcException {

    public SignatureException(String message) {
        super(message);
    }

    public SignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
