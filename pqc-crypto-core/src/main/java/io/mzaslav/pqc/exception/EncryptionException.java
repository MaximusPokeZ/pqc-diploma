package io.mzaslav.pqc.exception;

/**
 * Exception thrown when symmetric encryption/decryption fails.
 * <p>
 * AEAD encryption errors include:
 * <ul>
 *   <li>Authentication tag verification failure</li>
 *   <li>Invalid IV/nonce</li>
 *   <li>Corrupted ciphertext</li>
 * </ul>
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public class EncryptionException extends PqcException {

    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
