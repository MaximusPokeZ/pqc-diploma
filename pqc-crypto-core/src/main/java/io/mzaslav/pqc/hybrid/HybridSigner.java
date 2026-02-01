package io.mzaslav.pqc.hybrid;

import io.mzaslav.pqc.algorithm.MlDsaParameterSet;
import io.mzaslav.pqc.signature.MlDsaProvider;
import io.mzaslav.pqc.signature.SignatureKeyPair;
import io.mzaslav.pqc.signature.SignatureProvider;

import java.util.Objects;

/**
 * High-level post-quantum digital signature facade.
 * <p>
 * This class provides a simple, secure API for signing and verifying data
 * using ML-DSA (Module-Lattice Digital Signature Algorithm, FIPS 204).
 * </p>
 * <p>
 * <b>Security Features:</b>
 * <ul>
 *   <li>Post-quantum secure signatures based on lattice problems</li>
 *   <li>Resistance to quantum computing attacks</li>
 *   <li>NIST-standardized algorithm (FIPS 204)</li>
 * </ul>
 * </p>
 * <p>
 * <b>Signature Size Considerations:</b>
 * ML-DSA signatures are significantly larger than classical signatures:
 * <ul>
 *   <li>ML-DSA-44: 2420 bytes (vs ~64 bytes for Ed25519)</li>
 *   <li>ML-DSA-65: 3309 bytes (recommended)</li>
 *   <li>ML-DSA-87: 4627 bytes</li>
 * </ul>
 * Plan storage and bandwidth requirements accordingly.
 * </p>
 * <p>
 * Example usage:
 * <pre>{@code
 * // Create signer
 * HybridSigner signer = HybridSigner.create();
 * 
 * // Generate signing key pair
 * SignatureKeyPair keyPair = signer.generateKeyPair();
 * 
 * // Sign a message
 * byte[] message = "Important document".getBytes();
 * byte[] signature = signer.sign(keyPair, message);
 * 
 * // Verify signature
 * boolean valid = signer.verify(keyPair.getEncodedPublicKey(), message, signature);
 * }</pre>
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public final class HybridSigner {
    
    private final SignatureProvider signatureProvider;
    private final MlDsaParameterSet parameterSet;
    
    /**
     * Creates a new hybrid signer with the specified provider.
     *
     * @param signatureProvider the signature provider
     * @param parameterSet      the ML-DSA parameter set
     */
    private HybridSigner(SignatureProvider signatureProvider, MlDsaParameterSet parameterSet) {
        this.signatureProvider = signatureProvider;
        this.parameterSet = parameterSet;
    }
    
    /**
     * Creates a hybrid signer using ML-DSA-65 (recommended).
     *
     * @return a new hybrid signer
     */
    public static HybridSigner create() {
        return create(MlDsaParameterSet.ML_DSA_65);
    }
    
    /**
     * Creates a hybrid signer with the specified ML-DSA parameter set.
     *
     * @param parameterSet the ML-DSA parameter set
     * @return a new hybrid signer
     */
    public static HybridSigner create(MlDsaParameterSet parameterSet) {
        Objects.requireNonNull(parameterSet, "Parameter set cannot be null");
        MlDsaProvider provider = new MlDsaProvider(parameterSet);
        return new HybridSigner(provider, parameterSet);
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
     * Generates a new signing key pair.
     *
     * @return a new signature key pair
     */
    public SignatureKeyPair generateKeyPair() {
        return signatureProvider.generateKeyPair();
    }
    
    /**
     * Signs a message.
     *
     * @param keyPair the signing key pair
     * @param message the message to sign
     * @return the signature bytes
     */
    public byte[] sign(SignatureKeyPair keyPair, byte[] message) {
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        Objects.requireNonNull(message, "Message cannot be null");
        return signatureProvider.sign(keyPair, message);
    }
    
    /**
     * Verifies a signature on a message.
     *
     * @param encodedPublicKey the signer's encoded public key
     * @param message          the original message
     * @param signature        the signature to verify
     * @return true if the signature is valid
     */
    public boolean verify(byte[] encodedPublicKey, byte[] message, byte[] signature) {
        Objects.requireNonNull(encodedPublicKey, "Public key cannot be null");
        Objects.requireNonNull(message, "Message cannot be null");
        Objects.requireNonNull(signature, "Signature cannot be null");
        return signatureProvider.verify(encodedPublicKey, message, signature);
    }
    
    /**
     * Verifies a signature using a key pair.
     *
     * @param keyPair   the key pair containing the public key
     * @param message   the original message
     * @param signature the signature to verify
     * @return true if the signature is valid
     */
    public boolean verify(SignatureKeyPair keyPair, byte[] message, byte[] signature) {
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        return verify(keyPair.getEncodedPublicKey(), message, signature);
    }
    
    /**
     * Returns the signature size in bytes.
     *
     * @return the signature size
     */
    public int getSignatureSize() {
        return signatureProvider.getSignatureSize();
    }
    
    /**
     * Returns the public key size in bytes.
     *
     * @return the public key size
     */
    public int getPublicKeySize() {
        return parameterSet.getPublicKeySize();
    }
    
    /**
     * Returns the private key size in bytes.
     *
     * @return the private key size
     */
    public int getPrivateKeySize() {
        return parameterSet.getPrivateKeySize();
    }
    
    @Override
    public String toString() {
        return String.format("HybridSigner[%s]", parameterSet.getParameterName());
    }
}
