package io.mzaslav.pqc.signature;

import io.mzaslav.pqc.algorithm.MlDsaParameterSet;
import io.mzaslav.pqc.algorithm.SignatureAlgorithm;
import io.mzaslav.pqc.exception.KeyGenerationException;
import io.mzaslav.pqc.exception.SignatureException;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * ML-DSA (Module-Lattice Digital Signature Algorithm) provider.
 * <p>
 * Implements FIPS 204 ML-DSA using Java 25's native JEP 497 support.
 * This is a post-quantum digital signature scheme based on the
 * Module Learning With Errors problem.
 * </p>
 * <p>
 * <b>Signature Sizes:</b> ML-DSA signatures are significantly larger than
 * classical signatures:
 * <ul>
 *   <li>ML-DSA-44: 2420 bytes (vs ~64 bytes for Ed25519)</li>
 *   <li>ML-DSA-65: 3309 bytes</li>
 *   <li>ML-DSA-87: 4627 bytes</li>
 * </ul>
 * Plan storage and bandwidth accordingly.
 * </p>
 * <p>
 * Example usage:
 * <pre>{@code
 * MlDsaProvider provider = new MlDsaProvider(MlDsaParameterSet.ML_DSA_65);
 * 
 * // Generate signing key pair
 * SignatureKeyPair keyPair = provider.generateKeyPair();
 * 
 * // Sign a message
 * byte[] message = "Hello, post-quantum world!".getBytes();
 * byte[] signature = provider.sign(keyPair, message);
 * 
 * // Verify the signature
 * boolean valid = provider.verify(keyPair.getPublicKey(), message, signature);
 * // valid == true
 * }</pre>
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public final class MlDsaProvider implements SignatureProvider {
    
    private static final String ALGORITHM_NAME = "ML-DSA";
    
    private final MlDsaParameterSet parameterSet;
    private final KeyPairGenerator keyPairGenerator;
    private final KeyFactory keyFactory;
    
    /**
     * Creates a new ML-DSA provider with the specified parameter set.
     *
     * @param parameterSet the ML-DSA parameter set (44, 65, or 87)
     * @throws KeyGenerationException if the algorithm is not available
     */
    public MlDsaProvider(MlDsaParameterSet parameterSet) {
        this.parameterSet = Objects.requireNonNull(parameterSet, "Parameter set cannot be null");
        
        try {
            this.keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_NAME);
            this.keyPairGenerator.initialize(parameterSet.toParameterSpec());
            this.keyFactory = KeyFactory.getInstance(ALGORITHM_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenerationException(
                "ML-DSA algorithm not available. Ensure you are using Java 25+ with JEP 497 support.", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new KeyGenerationException(
                "Invalid ML-DSA parameter set: " + parameterSet.getParameterName(), e);
        }
    }
    
    /**
     * Creates a new ML-DSA provider with the default parameter set (ML-DSA-65).
     *
     * @throws KeyGenerationException if the algorithm is not available
     */
    public MlDsaProvider() {
        this(MlDsaParameterSet.getDefault());
    }
    
    @Override
    public synchronized SignatureKeyPair generateKeyPair() {
        try {
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return new SignatureKeyPair(SignatureAlgorithm.ML_DSA, keyPair.getPublic(), keyPair.getPrivate());
        } catch (Exception e) {
            throw new KeyGenerationException("Failed to generate ML-DSA key pair", e);
        }
    }
    
    @Override
    public byte[] sign(PrivateKey privateKey, byte[] message) {
        Objects.requireNonNull(privateKey, "Private key cannot be null");
        Objects.requireNonNull(message, "Message cannot be null");
        
        try {
            Signature signature = Signature.getInstance(ALGORITHM_NAME);
            signature.initSign(privateKey);
            signature.update(message);
            return signature.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException("ML-DSA algorithm not available", e);
        } catch (InvalidKeyException e) {
            throw new SignatureException("Invalid private key for ML-DSA signing", e);
        } catch (java.security.SignatureException e) {
            throw new SignatureException("Failed to sign message", e);
        }
    }
    
    @Override
    public byte[] sign(SignatureKeyPair keyPair, byte[] message) {
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        return sign(keyPair.getPrivateKey(), message);
    }
    
    @Override
    public boolean verify(PublicKey publicKey, byte[] message, byte[] signatureBytes) {
        Objects.requireNonNull(publicKey, "Public key cannot be null");
        Objects.requireNonNull(message, "Message cannot be null");
        Objects.requireNonNull(signatureBytes, "Signature cannot be null");
        
        try {
            Signature signature = Signature.getInstance(ALGORITHM_NAME);
            signature.initVerify(publicKey);
            signature.update(message);
            return signature.verify(signatureBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException("ML-DSA algorithm not available", e);
        } catch (InvalidKeyException e) {
            throw new SignatureException("Invalid public key for ML-DSA verification", e);
        } catch (java.security.SignatureException e) {
            // Signature verification failed - this is normal for invalid signatures
            return false;
        }
    }
    
    @Override
    public boolean verify(byte[] encodedPublicKey, byte[] message, byte[] signatureBytes) {
        Objects.requireNonNull(encodedPublicKey, "Encoded public key cannot be null");
        
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedPublicKey);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            return verify(publicKey, message, signatureBytes);
        } catch (InvalidKeySpecException e) {
            throw new SignatureException("Invalid encoded public key format", e);
        }
    }
    
    @Override
    public int getSignatureSize() {
        return parameterSet.getSignatureSize();
    }

    @Override
    public SignatureAlgorithm getAlgorithm() { return SignatureAlgorithm.ML_DSA; }

    @Override
    public byte[] sign(byte[] encodedPrivateKey, byte[] message) {
        try {
            java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(encodedPrivateKey);
            PrivateKey privKey = keyFactory.generatePrivate(keySpec);
            return sign(privKey, message);
        } catch (java.security.spec.InvalidKeySpecException e) {
            throw new io.mzaslav.pqc.exception.SignatureException("Invalid encoded ML-DSA private key format", e);
        }
    }

    public MlDsaParameterSet getParameterSet() {
        return parameterSet;
    }
    
    @Override
    public String toString() {
        return String.format("MlDsaProvider[%s]", parameterSet.getParameterName());
    }
}
