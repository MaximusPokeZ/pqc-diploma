package io.mzaslav.pqc.kem;

import io.mzaslav.pqc.algorithm.KemAlgorithm;

import java.security.PublicKey;

/**
 * Interface for Key Encapsulation Mechanism (KEM) providers.
 * <p>
 * A KEM allows one party to securely establish a shared secret with another
 * party using only their public key. The encapsulation operation creates
 * a ciphertext and a shared secret; the decapsulation operation recovers
 * the same shared secret from the ciphertext using the private key.
 * </p>
 * <p>
 * Implementations of this interface provide:
 * <ul>
 *   <li>{@link #generateKeyPair()} - Generate a new KEM key pair</li>
 *   <li>{@link #encapsulate(PublicKey)} - Encapsulate to recipient's public key</li>
 *   <li>{@link #decapsulate(KemKeyPair, byte[])} - Decapsulate using private key</li>
 * </ul>
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public interface KemProvider {
    
    /**
     * Returns the KEM algorithm implemented by this provider.
     *
     * @return the algorithm
     */
    KemAlgorithm getAlgorithm();
    
    /**
     * Generates a new KEM key pair.
     *
     * @return a new key pair
     * @throws io.mzaslav.pqc.exception.KeyGenerationException if key generation fails
     */
    KemKeyPair generateKeyPair();
    
    /**
     * Encapsulates a shared secret to the recipient's public key.
     * <p>
     * This operation:
     * <ol>
     *   <li>Generates a random shared secret</li>
     *   <li>Encrypts the secret to the recipient's public key</li>
     *   <li>Returns both the ciphertext and the shared secret</li>
     * </ol>
     * </p>
     *
     * @param recipientPublicKey the recipient's public key
     * @return the encapsulation result containing ciphertext and shared secret
     * @throws io.mzaslav.pqc.exception.EncapsulationException if encapsulation fails
     */
    EncapsulationResult encapsulate(PublicKey recipientPublicKey);
    
    /**
     * Encapsulates a shared secret using raw encoded public key bytes.
     *
     * @param encodedPublicKey the recipient's encoded public key
     * @return the encapsulation result containing ciphertext and shared secret
     * @throws io.mzaslav.pqc.exception.EncapsulationException if encapsulation fails
     */
    EncapsulationResult encapsulate(byte[] encodedPublicKey);
    
    /**
     * Decapsulates a ciphertext to recover the shared secret.
     *
     * @param keyPair    the key pair containing the private key
     * @param ciphertext the ciphertext from encapsulation
     * @return the recovered shared secret
     * @throws io.mzaslav.pqc.exception.EncapsulationException if decapsulation fails
     */
    byte[] decapsulate(KemKeyPair keyPair, byte[] ciphertext);
    
    /**
     * Returns the expected ciphertext size in bytes for this algorithm.
     *
     * @return the ciphertext size
     */
    int getCiphertextSize();
    
    /**
     * Returns the shared secret size in bytes for this algorithm.
     *
     * @return the shared secret size
     */
    int getSharedSecretSize();
}
