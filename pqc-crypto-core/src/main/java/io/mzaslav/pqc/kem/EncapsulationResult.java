package io.mzaslav.pqc.kem;

import io.mzaslav.pqc.algorithm.KemAlgorithm;
import io.mzaslav.pqc.util.SecureBytes;

import java.util.Objects;

/**
 * Represents the result of a KEM encapsulation operation.
 * <p>
 * A KEM encapsulation produces two outputs:
 * <ul>
 *   <li><b>Ciphertext</b> - The encapsulated key material to send to the recipient</li>
 *   <li><b>Shared Secret</b> - The symmetric key derived from the encapsulation</li>
 * </ul>
 * </p>
 * <p>
 * <b>Security Note:</b> The shared secret should be used immediately for
 * key derivation or encryption and then wiped from memory using {@link #destroy()}.
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public final class EncapsulationResult implements AutoCloseable {
    
    private final KemAlgorithm algorithm;
    private final byte[] ciphertext;
    private byte[] sharedSecret;
    private volatile boolean destroyed;
    
    /**
     * Creates a new encapsulation result.
     *
     * @param algorithm    the KEM algorithm used
     * @param ciphertext   the encapsulated key (ciphertext)
     * @param sharedSecret the derived shared secret
     */
    public EncapsulationResult(KemAlgorithm algorithm, byte[] ciphertext, byte[] sharedSecret) {
        this.algorithm = Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        this.ciphertext = Objects.requireNonNull(SecureBytes.copy(ciphertext), "Ciphertext cannot be null");
        this.sharedSecret = Objects.requireNonNull(SecureBytes.copy(sharedSecret), "Shared secret cannot be null");
        this.destroyed = false;
    }
    
    /**
     * Returns the KEM algorithm used.
     *
     * @return the algorithm
     */
    public KemAlgorithm getAlgorithm() {
        return algorithm;
    }
    
    /**
     * Returns a copy of the ciphertext (encapsulated key).
     * <p>
     * This is the data that should be sent to the recipient.
     * </p>
     *
     * @return the ciphertext
     * @throws IllegalStateException if the result has been destroyed
     */
    public byte[] getCiphertext() {
        checkNotDestroyed();
        return SecureBytes.copy(ciphertext);
    }
    
    /**
     * Returns a copy of the shared secret.
     * <p>
     * Use this secret for key derivation (e.g., HKDF) or directly
     * as a symmetric encryption key.
     * </p>
     *
     * @return the shared secret
     * @throws IllegalStateException if the result has been destroyed
     */
    public byte[] getSharedSecret() {
        checkNotDestroyed();
        return SecureBytes.copy(sharedSecret);
    }
    
    /**
     * Returns the size of the ciphertext in bytes.
     *
     * @return the ciphertext size
     */
    public int getCiphertextSize() {
        return ciphertext.length;
    }
    
    /**
     * Returns the size of the shared secret in bytes.
     *
     * @return the shared secret size
     */
    public int getSharedSecretSize() {
        return sharedSecret != null ? sharedSecret.length : 0;
    }
    
    /**
     * Securely wipes the shared secret from memory.
     * After calling this method, the shared secret cannot be retrieved.
     */
    public void destroy() {
        if (!destroyed) {
            SecureBytes.wipe(sharedSecret);
            sharedSecret = null;
            destroyed = true;
        }
    }
    
    /**
     * Checks if this result has been destroyed.
     *
     * @return true if destroyed
     */
    public boolean isDestroyed() {
        return destroyed;
    }
    
    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("Encapsulation result has been destroyed");
        }
    }
    
    @Override
    public void close() {
        destroy();
    }
    
    @Override
    public String toString() {
        return String.format("EncapsulationResult[algorithm=%s, ciphertextSize=%d, secretSize=%d, destroyed=%s]",
            algorithm, getCiphertextSize(), getSharedSecretSize(), destroyed);
    }
}
