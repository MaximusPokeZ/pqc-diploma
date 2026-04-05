package io.mzaslav.pqc.hybrid;

import io.mzaslav.pqc.algorithm.ClassicalSigAlgorithm;
import io.mzaslav.pqc.algorithm.MlDsaParameterSet;
import io.mzaslav.pqc.signature.ClassicalSignatureProvider;
import io.mzaslav.pqc.signature.HybridSignatureProvider;
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
    private final MlDsaParameterSet parameterSet; // Может быть null для CLASSICAL_ONLY режима

    /**
     * Creates a new hybrid signer with the specified provider.
     */
    private HybridSigner(SignatureProvider signatureProvider, MlDsaParameterSet parameterSet) {
        this.signatureProvider = signatureProvider;
        this.parameterSet = parameterSet;
    }

    // =========================================================================
    // 1. PQC-ONLY MODE (Только квантово-устойчивая подпись)
    // =========================================================================
    public static HybridSigner createPqcOnly(MlDsaParameterSet parameterSet) {
        Objects.requireNonNull(parameterSet, "Parameter set cannot be null");
        MlDsaProvider provider = new MlDsaProvider(parameterSet);
        return new HybridSigner(provider, parameterSet);
    }

    // =========================================================================
    // 2. HYBRID MODE (Ed25519/ECDSA + ML-DSA) - Рекомендуется
    // =========================================================================

    /**
     * Creates a hybrid signer using Ed25519 + ML-DSA-65 (recommended default).
     */
    public static HybridSigner create() {
        return create(ClassicalSigAlgorithm.ED25519, MlDsaParameterSet.ML_DSA_65);
    }

    /**
     * Creates a hybrid signer using Ed25519 and a specified ML-DSA parameter set.
     */
    public static HybridSigner create(MlDsaParameterSet parameterSet) {
        return create(ClassicalSigAlgorithm.ED25519, parameterSet);
    }

    /**
     * Creates a hybrid signer with manual selection of both algorithms.
     */
    public static HybridSigner create(ClassicalSigAlgorithm classicalAlgo, MlDsaParameterSet mlDsaParameterSet) {
        Objects.requireNonNull(classicalAlgo, "Classical algorithm cannot be null");
        Objects.requireNonNull(mlDsaParameterSet, "Parameter set cannot be null");

        ClassicalSignatureProvider classicalProvider = new ClassicalSignatureProvider(classicalAlgo);
        HybridSignatureProvider hybridProvider = new HybridSignatureProvider(classicalProvider, mlDsaParameterSet);

        return new HybridSigner(hybridProvider, mlDsaParameterSet);
    }

    // =========================================================================
    // 3. CLASSICAL-ONLY MODE (Ed25519, ECDSA_P256, RSA_2048)
    // =========================================================================
    public static HybridSigner createClassicalOnly(ClassicalSigAlgorithm classicalAlgo) {
        Objects.requireNonNull(classicalAlgo, "Classical algorithm cannot be null");
        ClassicalSignatureProvider provider = new ClassicalSignatureProvider(classicalAlgo);
        return new HybridSigner(provider, null);
    }

    // =========================================================================
    // КРИПТОГРАФИЧЕСКИЕ МЕТОДЫ (Без изменений)
    // =========================================================================

    public MlDsaParameterSet getParameterSet() {
        return parameterSet;
    }

    public SignatureKeyPair generateKeyPair() {
        return signatureProvider.generateKeyPair();
    }

    public byte[] sign(SignatureKeyPair keyPair, byte[] message) {
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        Objects.requireNonNull(message, "Message cannot be null");
        return signatureProvider.sign(keyPair, message);
    }

    public boolean verify(byte[] encodedPublicKey, byte[] message, byte[] signature) {
        Objects.requireNonNull(encodedPublicKey, "Public key cannot be null");
        Objects.requireNonNull(message, "Message cannot be null");
        Objects.requireNonNull(signature, "Signature cannot be null");
        return signatureProvider.verify(encodedPublicKey, message, signature);
    }

    public boolean verify(SignatureKeyPair keyPair, byte[] message, byte[] signature) {
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        return verify(keyPair.getEncodedPublicKey(), message, signature);
    }

    public int getSignatureSize() {
        return signatureProvider.getSignatureSize();
    }

    public int getPublicKeySize() {
        // У классики размер ключа варьируется, в PQC он жестко зафиксирован
        return parameterSet != null ? parameterSet.getPublicKeySize() : -1;
    }

    public int getPrivateKeySize() {
        return parameterSet != null ? parameterSet.getPrivateKeySize() : -1;
    }

    @Override
    public String toString() {
        if (parameterSet != null) {
            return String.format("HybridSigner[Mode=%s, PQC=%s]",
                    signatureProvider.getAlgorithm(), parameterSet.getParameterName());
        }
        return String.format("HybridSigner[Mode=%s]", signatureProvider.getAlgorithm());
    }
}
