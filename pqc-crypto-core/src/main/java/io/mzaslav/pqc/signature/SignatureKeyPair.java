package io.mzaslav.pqc.signature;

import io.mzaslav.pqc.algorithm.MlDsaParameterSet;
import io.mzaslav.pqc.util.SecureBytes;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Represents a key pair for digital signature operations.
 * <p>
 * This class encapsulates both the public (verification) and private (signing)
 * keys along with metadata about the algorithm used.
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
public final class SignatureKeyPair implements AutoCloseable {
    
    private final MlDsaParameterSet parameterSet;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final byte[] encodedPublicKey;
    private final byte[] encodedPrivateKey;
    private volatile boolean destroyed;
    
    /**
     * Creates a new signature key pair.
     *
     * @param parameterSet the ML-DSA parameter set used
     * @param publicKey    the public (verification) key
     * @param privateKey   the private (signing) key
     */
    public SignatureKeyPair(MlDsaParameterSet parameterSet, PublicKey publicKey, PrivateKey privateKey) {
        this.parameterSet = Objects.requireNonNull(parameterSet, "Parameter set cannot be null");
        this.publicKey = Objects.requireNonNull(publicKey, "Public key cannot be null");
        this.privateKey = Objects.requireNonNull(privateKey, "Private key cannot be null");
        this.encodedPublicKey = publicKey.getEncoded();
        this.encodedPrivateKey = privateKey.getEncoded();
        this.destroyed = false;
    }
    
    /**
     * Returns the ML-DSA parameter set.
     *
     * @return the parameter set
     */
    public MlDsaParameterSet getParameterSet() {
        return parameterSet;
    }
    
    /**
     * Returns the public (verification) key.
     *
     * @return the public key
     * @throws IllegalStateException if the key pair has been destroyed
     */
    public PublicKey getPublicKey() {
        checkNotDestroyed();
        return publicKey;
    }
    
    /**
     * Returns the private (signing) key.
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
     * @return the encoded public key
     * @throws IllegalStateException if the key pair has been destroyed
     */
    public byte[] getEncodedPublicKey() {
        checkNotDestroyed();
        return SecureBytes.copy(encodedPublicKey);
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
     * After calling this method, the key pair cannot be used for signing.
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
        return String.format("SignatureKeyPair[%s, publicKeySize=%d, destroyed=%s]",
            parameterSet.getParameterName(), getPublicKeySize(), destroyed);
    }
}
