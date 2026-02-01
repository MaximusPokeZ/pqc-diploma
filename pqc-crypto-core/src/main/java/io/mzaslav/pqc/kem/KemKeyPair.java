package io.mzaslav.pqc.kem;

import io.mzaslav.pqc.algorithm.KemAlgorithm;
import io.mzaslav.pqc.util.SecureBytes;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Represents a key pair for Key Encapsulation Mechanism (KEM) operations.
 * <p>
 * This class encapsulates both the public and private keys along with
 * metadata about the algorithm used. For hybrid KEM operations, this
 * contains the combined key material from both classical and PQC algorithms.
 * </p>
 * <p>
 * <b>Security Note:</b> Instances of this class contain sensitive private key
 * material. Use {@link #destroy()} to securely wipe the private key when
 * it is no longer needed.
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public final class KemKeyPair implements AutoCloseable {
    
    private final KemAlgorithm algorithm;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final byte[] encodedPublicKey;
    private final byte[] encodedPrivateKey;
    private volatile boolean destroyed;
    
    /**
     * Creates a new KEM key pair.
     *
     * @param algorithm  the KEM algorithm used
     * @param publicKey  the public key
     * @param privateKey the private key
     */
    public KemKeyPair(KemAlgorithm algorithm, PublicKey publicKey, PrivateKey privateKey) {
        this.algorithm = Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        this.publicKey = Objects.requireNonNull(publicKey, "Public key cannot be null");
        this.privateKey = Objects.requireNonNull(privateKey, "Private key cannot be null");
        this.encodedPublicKey = publicKey.getEncoded();
        this.encodedPrivateKey = privateKey.getEncoded();
        this.destroyed = false;
    }
    
    /**
     * Creates a KEM key pair for decapsulation only (private key required).
     * <p>
     * This constructor is used internally when only the private key is needed
     * for decapsulation operations.
     * </p>
     *
     * @param algorithm  the KEM algorithm used
     * @param privateKey the private key
     */
    KemKeyPair(KemAlgorithm algorithm, PrivateKey privateKey) {
        this.algorithm = Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        this.publicKey = null;
        this.privateKey = Objects.requireNonNull(privateKey, "Private key cannot be null");
        this.encodedPublicKey = null;
        this.encodedPrivateKey = privateKey.getEncoded();
        this.destroyed = false;
    }
    
    /**
     * Creates a new KEM key pair from raw encoded keys (for hybrid keys).
     *
     * @param algorithm         the KEM algorithm used
     * @param publicKey         the JCA public key (may be composite)
     * @param privateKey        the JCA private key (may be composite)
     * @param encodedPublicKey  the combined encoded public key bytes
     * @param encodedPrivateKey the combined encoded private key bytes
     */
    public KemKeyPair(KemAlgorithm algorithm, PublicKey publicKey, PrivateKey privateKey,
                      byte[] encodedPublicKey, byte[] encodedPrivateKey) {
        this.algorithm = Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.encodedPublicKey = SecureBytes.copy(encodedPublicKey);
        this.encodedPrivateKey = SecureBytes.copy(encodedPrivateKey);
        this.destroyed = false;
    }
    
    /**
     * Returns the KEM algorithm.
     *
     * @return the algorithm
     */
    public KemAlgorithm getAlgorithm() {
        return algorithm;
    }
    
    /**
     * Returns the public key.
     *
     * @return the public key, or null if this is a private-key-only pair
     * @throws IllegalStateException if the key pair has been destroyed
     */
    public PublicKey getPublicKey() {
        checkNotDestroyed();
        return publicKey;
    }
    
    /**
     * Checks if this key pair has a public key.
     *
     * @return true if public key is available
     */
    public boolean hasPublicKey() {
        return publicKey != null;
    }
    
    /**
     * Returns the private key.
     *
     * @return the private key
     * @throws IllegalStateException if the key pair has been destroyed
     */
    public PrivateKey getPrivateKey() {
        checkNotDestroyed();
        return privateKey;
    }
    
    /**
     * Returns a copy of the encoded public key bytes.
     *
     * @return the encoded public key, or null if this is a private-key-only pair
     * @throws IllegalStateException if the key pair has been destroyed
     */
    public byte[] getEncodedPublicKey() {
        checkNotDestroyed();
        return encodedPublicKey != null ? SecureBytes.copy(encodedPublicKey) : null;
    }
    
    /**
     * Returns a copy of the encoded private key bytes.
     *
     * @return the encoded private key
     * @throws IllegalStateException if the key pair has been destroyed
     */
    public byte[] getEncodedPrivateKey() {
        checkNotDestroyed();
        return SecureBytes.copy(encodedPrivateKey);
    }
    
    /**
     * Returns the size of the public key in bytes.
     *
     * @return the public key size
     */
    public int getPublicKeySize() {
        return encodedPublicKey != null ? encodedPublicKey.length : 0;
    }
    
    /**
     * Returns the size of the private key in bytes.
     *
     * @return the private key size
     */
    public int getPrivateKeySize() {
        return encodedPrivateKey != null ? encodedPrivateKey.length : 0;
    }
    
    /**
     * Securely destroys the private key material.
     * After calling this method, the key pair cannot be used.
     */
    public void destroy() {
        if (!destroyed) {
            SecureBytes.wipe(encodedPrivateKey);
            destroyed = true;
        }
    }
    
    /**
     * Checks if this key pair has been destroyed.
     *
     * @return true if destroyed
     */
    public boolean isDestroyed() {
        return destroyed;
    }
    
    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("Key pair has been destroyed");
        }
    }
    
    @Override
    public void close() {
        destroy();
    }
    
    @Override
    public String toString() {
        return String.format("KemKeyPair[algorithm=%s, publicKeySize=%d, destroyed=%s]",
            algorithm, getPublicKeySize(), destroyed);
    }
}
