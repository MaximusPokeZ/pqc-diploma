package io.mzaslav.pqc.kem;

import io.mzaslav.pqc.algorithm.KemAlgorithm;
import io.mzaslav.pqc.exception.EncapsulationException;
import io.mzaslav.pqc.exception.KeyGenerationException;
import io.mzaslav.pqc.util.SecureBytes;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * X25519 Elliptic Curve Diffie-Hellman KEM provider.
 * <p>
 * This provider implements a KEM-style interface on top of X25519 ECDH.
 * The encapsulation generates an ephemeral key pair and performs ECDH
 * with the recipient's public key.
 * </p>
 * <p>
 * While X25519 is not quantum-resistant, it provides:
 * <ul>
 *   <li>High performance (faster than ML-KEM)</li>
 *   <li>Small key and ciphertext sizes</li>
 *   <li>Well-established security against classical computers</li>
 * </ul>
 * </p>
 * <p>
 * In the hybrid scheme, X25519 acts as a fallback if ML-KEM is broken,
 * ensuring security remains as strong as the strongest algorithm.
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public final class X25519Provider implements KemProvider {
    
    private static final String ALGORITHM_NAME = "X25519";
    private static final int PUBLIC_KEY_SIZE = 32;
    private static final int SHARED_SECRET_SIZE = 32;
    
    private final KeyPairGenerator keyPairGenerator;
    private final KeyFactory keyFactory;
    
    /**
     * Creates a new X25519 KEM provider.
     *
     * @throws KeyGenerationException if the algorithm is not available
     */
    public X25519Provider() {
        try {
            this.keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_NAME);
            this.keyPairGenerator.initialize(new NamedParameterSpec(ALGORITHM_NAME));
            this.keyFactory = KeyFactory.getInstance(ALGORITHM_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenerationException("X25519 algorithm not available", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new KeyGenerationException("Failed to initialize X25519 key generator", e);
        }
    }
    
    @Override
    public KemAlgorithm getAlgorithm() {
        return KemAlgorithm.X25519;
    }
    
    @Override
    public synchronized KemKeyPair generateKeyPair() {
        try {
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return new KemKeyPair(KemAlgorithm.X25519, keyPair.getPublic(), keyPair.getPrivate());
        } catch (Exception e) {
            throw new KeyGenerationException("Failed to generate X25519 key pair", e);
        }
    }
    
    @Override
    public EncapsulationResult encapsulate(PublicKey recipientPublicKey) {
        Objects.requireNonNull(recipientPublicKey, "Recipient public key cannot be null");
        
        try {
            // Generate ephemeral key pair
            KeyPair ephemeralKeyPair = keyPairGenerator.generateKeyPair();
            
            // Perform ECDH
            KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM_NAME);
            keyAgreement.init(ephemeralKeyPair.getPrivate());
            keyAgreement.doPhase(recipientPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();
            
            // The ciphertext is the ephemeral public key
            byte[] ciphertext = ephemeralKeyPair.getPublic().getEncoded();
            
            return new EncapsulationResult(KemAlgorithm.X25519, ciphertext, sharedSecret);
        } catch (NoSuchAlgorithmException e) {
            throw new EncapsulationException("X25519 algorithm not available", e);
        } catch (InvalidKeyException e) {
            throw new EncapsulationException("Invalid public key for X25519 key agreement", e);
        }
    }
    
    @Override
    public EncapsulationResult encapsulate(byte[] encodedPublicKey) {
        Objects.requireNonNull(encodedPublicKey, "Encoded public key cannot be null");
        
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedPublicKey);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            return encapsulate(publicKey);
        } catch (InvalidKeySpecException e) {
            throw new EncapsulationException("Invalid encoded public key format", e);
        }
    }
    
    @Override
    public byte[] decapsulate(KemKeyPair keyPair, byte[] ciphertext) {
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");
        
        try {
            // The ciphertext is the sender's ephemeral public key
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(ciphertext);
            PublicKey ephemeralPublicKey = keyFactory.generatePublic(keySpec);
            
            // Perform ECDH with our private key and sender's ephemeral public key
            KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM_NAME);
            keyAgreement.init(keyPair.getPrivateKey());
            keyAgreement.doPhase(ephemeralPublicKey, true);
            
            return keyAgreement.generateSecret();
        } catch (NoSuchAlgorithmException e) {
            throw new EncapsulationException("X25519 algorithm not available", e);
        } catch (InvalidKeyException | InvalidKeySpecException e) {
            throw new EncapsulationException("X25519 decapsulation failed - invalid key", e);
        }
    }
    
    @Override
    public int getCiphertextSize() {
        // X.509 encoded X25519 public key is typically 44 bytes (12 header + 32 key)
        return 44;
    }
    
    @Override
    public int getSharedSecretSize() {
        return SHARED_SECRET_SIZE;
    }
    
    @Override
    public String toString() {
        return "X25519Provider";
    }
}
