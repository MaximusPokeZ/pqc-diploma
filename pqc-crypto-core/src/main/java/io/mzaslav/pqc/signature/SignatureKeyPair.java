package io.mzaslav.pqc.signature;

import io.mzaslav.pqc.algorithm.SignatureAlgorithm;
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

    private final SignatureAlgorithm algorithm;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final byte[] encodedPublicKey;
    private final byte[] encodedPrivateKey;
    private volatile boolean destroyed;

    public SignatureKeyPair(SignatureAlgorithm algorithm, PublicKey publicKey, PrivateKey privateKey) {
        this.algorithm = Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        this.publicKey = Objects.requireNonNull(publicKey, "Public key cannot be null");
        this.privateKey = Objects.requireNonNull(privateKey, "Private key cannot be null");
        this.encodedPublicKey = publicKey.getEncoded();
        this.encodedPrivateKey = privateKey.getEncoded();
        this.destroyed = false;
    }

    public SignatureKeyPair(SignatureAlgorithm algorithm, PublicKey publicKey, PrivateKey privateKey,
                            byte[] encodedPublicKey, byte[] encodedPrivateKey) {
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.encodedPublicKey = SecureBytes.copy(encodedPublicKey);
        this.encodedPrivateKey = SecureBytes.copy(encodedPrivateKey);
        this.destroyed = false;
    }

    public SignatureAlgorithm getAlgorithm() { return algorithm; }

    public PublicKey getPublicKey() {
        checkNotDestroyed();
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        checkNotDestroyed();
        return privateKey;
    }

    public byte[] getEncodedPublicKey() {
        checkNotDestroyed();
        return SecureBytes.copy(encodedPublicKey);
    }

    public byte[] getEncodedPrivateKey() {
        checkNotDestroyed();
        return SecureBytes.copy(encodedPrivateKey);
    }

    public void destroy() {
        if (!destroyed) {
            SecureBytes.wipe(encodedPrivateKey);
            destroyed = true;
        }
    }

    private void checkNotDestroyed() {
        if (destroyed) throw new IllegalStateException("Signature key pair has been destroyed");
    }

    @Override
    public void close() { destroy(); }
}
