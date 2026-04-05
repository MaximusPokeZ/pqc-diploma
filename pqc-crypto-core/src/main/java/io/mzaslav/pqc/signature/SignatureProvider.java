package io.mzaslav.pqc.signature;

import io.mzaslav.pqc.algorithm.MlDsaParameterSet;
import io.mzaslav.pqc.algorithm.SignatureAlgorithm;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Interface for digital signature providers.
 * <p>
 * A digital signature scheme allows one party to sign a message using their
 * private key, and anyone to verify the signature using the signer's public key.
 * </p>
 * <p>
 * Implementations of this interface provide:
 * <ul>
 *   <li>{@link #generateKeyPair()} - Generate a new signing key pair</li>
 *   <li>{@link #sign(PrivateKey, byte[])} - Sign a message</li>
 *   <li>{@link #verify(PublicKey, byte[], byte[])} - Verify a signature</li>
 * </ul>
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public interface SignatureProvider {

    /**
     * Returns the algorithm implemented by this provider.
     */
    SignatureAlgorithm getAlgorithm();

    /**
     * Generates a new signing key pair.
     */
    SignatureKeyPair generateKeyPair();

    /**
     * Signs a message using a JCA private key.
     */
    byte[] sign(PrivateKey privateKey, byte[] message);

    /**
     * Signs a message using raw encoded private key bytes.
     * (Crucial for Hybrid Composites)
     */
    byte[] sign(byte[] encodedPrivateKey, byte[] message);

    /**
     * Signs a message using a signature key pair.
     */
    byte[] sign(SignatureKeyPair keyPair, byte[] message);

    /**
     * Verifies a signature using a JCA public key.
     */
    boolean verify(PublicKey publicKey, byte[] message, byte[] signature);

    /**
     * Verifies a signature using raw encoded public key bytes.
     */
    boolean verify(byte[] encodedPublicKey, byte[] message, byte[] signature);

    /**
     * Returns the expected signature size in bytes.
     */
    int getSignatureSize();
}
