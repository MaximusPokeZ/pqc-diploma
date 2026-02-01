package io.mzaslav.pqc.signature;

import io.mzaslav.pqc.algorithm.MlDsaParameterSet;

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
     * Returns the ML-DSA parameter set implemented by this provider.
     *
     * @return the parameter set
     */
    MlDsaParameterSet getParameterSet();
    
    /**
     * Generates a new signing key pair.
     *
     * @return a new key pair
     * @throws io.mzaslav.pqc.exception.KeyGenerationException if key generation fails
     */
    SignatureKeyPair generateKeyPair();
    
    /**
     * Signs a message using the private key.
     *
     * @param privateKey the private (signing) key
     * @param message    the message to sign
     * @return the signature bytes
     * @throws io.mzaslav.pqc.exception.SignatureException if signing fails
     */
    byte[] sign(PrivateKey privateKey, byte[] message);
    
    /**
     * Signs a message using a signature key pair.
     *
     * @param keyPair the key pair containing the private key
     * @param message the message to sign
     * @return the signature bytes
     * @throws io.mzaslav.pqc.exception.SignatureException if signing fails
     */
    byte[] sign(SignatureKeyPair keyPair, byte[] message);
    
    /**
     * Verifies a signature on a message using the public key.
     *
     * @param publicKey the public (verification) key
     * @param message   the original message
     * @param signature the signature to verify
     * @return true if the signature is valid, false otherwise
     * @throws io.mzaslav.pqc.exception.SignatureException if verification fails due to an error
     */
    boolean verify(PublicKey publicKey, byte[] message, byte[] signature);
    
    /**
     * Verifies a signature using an encoded public key.
     *
     * @param encodedPublicKey the encoded public key
     * @param message          the original message
     * @param signature        the signature to verify
     * @return true if the signature is valid, false otherwise
     * @throws io.mzaslav.pqc.exception.SignatureException if verification fails due to an error
     */
    boolean verify(byte[] encodedPublicKey, byte[] message, byte[] signature);
    
    /**
     * Returns the expected signature size in bytes for this algorithm.
     *
     * @return the signature size
     */
    int getSignatureSize();
}
