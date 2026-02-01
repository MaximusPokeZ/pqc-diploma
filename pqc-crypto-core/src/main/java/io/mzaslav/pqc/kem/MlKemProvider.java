package io.mzaslav.pqc.kem;

import io.mzaslav.pqc.algorithm.KemAlgorithm;
import io.mzaslav.pqc.algorithm.MlKemParameterSet;
import io.mzaslav.pqc.exception.EncapsulationException;
import io.mzaslav.pqc.exception.KeyGenerationException;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * ML-KEM (Module-Lattice Key Encapsulation Mechanism) provider.
 * <p>
 * Implements FIPS 203 ML-KEM using Java 25's native JEP 496 support.
 * This is a post-quantum KEM based on the Module Learning With Errors problem.
 * </p>
 * <p>
 * Example usage:
 * <pre>{@code
 * MlKemProvider provider = new MlKemProvider(MlKemParameterSet.ML_KEM_768);
 * 
 * // Recipient generates key pair
 * KemKeyPair keyPair = provider.generateKeyPair();
 * 
 * // Sender encapsulates to recipient's public key
 * EncapsulationResult result = provider.encapsulate(keyPair.getPublicKey());
 * byte[] ciphertext = result.getCiphertext();
 * byte[] senderSecret = result.getSharedSecret();
 * 
 * // Recipient decapsulates
 * byte[] recipientSecret = provider.decapsulate(keyPair, ciphertext);
 * // senderSecret equals recipientSecret
 * }</pre>
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public final class MlKemProvider implements KemProvider {
    
    private static final String ALGORITHM_NAME = "ML-KEM";
    
    private final MlKemParameterSet parameterSet;
    private final KeyPairGenerator keyPairGenerator;
    private final KEM kem;
    private final KeyFactory keyFactory;
    
    /**
     * Creates a new ML-KEM provider with the specified parameter set.
     *
     * @param parameterSet the ML-KEM parameter set (512, 768, or 1024)
     * @throws KeyGenerationException if the algorithm is not available
     */
    public MlKemProvider(MlKemParameterSet parameterSet) {
        this.parameterSet = Objects.requireNonNull(parameterSet, "Parameter set cannot be null");
        
        try {
            this.keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_NAME);
            this.keyPairGenerator.initialize(parameterSet.toParameterSpec());
            
            this.kem = KEM.getInstance(ALGORITHM_NAME);
            this.keyFactory = KeyFactory.getInstance(ALGORITHM_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenerationException(
                "ML-KEM algorithm not available. Ensure you are using Java 25+ with JEP 496 support.", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new KeyGenerationException(
                "Invalid ML-KEM parameter set: " + parameterSet.getParameterName(), e);
        }
    }
    
    /**
     * Creates a new ML-KEM provider with the default parameter set (ML-KEM-768).
     *
     * @throws KeyGenerationException if the algorithm is not available
     */
    public MlKemProvider() {
        this(MlKemParameterSet.getDefault());
    }
    
    /**
     * Returns the ML-KEM parameter set.
     *
     * @return the parameter set
     */
    public MlKemParameterSet getParameterSet() {
        return parameterSet;
    }
    
    @Override
    public KemAlgorithm getAlgorithm() {
        return KemAlgorithm.ML_KEM;
    }
    
    @Override
    public synchronized KemKeyPair generateKeyPair() {
        try {
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return new KemKeyPair(KemAlgorithm.ML_KEM, keyPair.getPublic(), keyPair.getPrivate());
        } catch (Exception e) {
            throw new KeyGenerationException("Failed to generate ML-KEM key pair", e);
        }
    }
    
    @Override
    public EncapsulationResult encapsulate(PublicKey recipientPublicKey) {
        Objects.requireNonNull(recipientPublicKey, "Recipient public key cannot be null");
        
        try {
            KEM.Encapsulator encapsulator = kem.newEncapsulator(recipientPublicKey);
            KEM.Encapsulated encapsulated = encapsulator.encapsulate();
            
            SecretKey secretKey = encapsulated.key();
            byte[] ciphertext = encapsulated.encapsulation();
            byte[] sharedSecret = secretKey.getEncoded();
            
            return new EncapsulationResult(KemAlgorithm.ML_KEM, ciphertext, sharedSecret);
        } catch (InvalidKeyException e) {
            throw new EncapsulationException("Invalid public key for ML-KEM encapsulation", e);
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
            KEM.Decapsulator decapsulator = kem.newDecapsulator(keyPair.getPrivateKey());
            SecretKey secretKey = decapsulator.decapsulate(ciphertext);
            return secretKey.getEncoded();
        } catch (InvalidKeyException e) {
            throw new EncapsulationException("Invalid private key for ML-KEM decapsulation", e);
        } catch (DecapsulateException e) {
            throw new EncapsulationException("ML-KEM decapsulation failed - invalid ciphertext", e);
        }
    }
    
    @Override
    public int getCiphertextSize() {
        return parameterSet.getCiphertextSize();
    }
    
    @Override
    public int getSharedSecretSize() {
        return parameterSet.getSharedSecretSize();
    }
    
    @Override
    public String toString() {
        return String.format("MlKemProvider[%s]", parameterSet.getParameterName());
    }
}
