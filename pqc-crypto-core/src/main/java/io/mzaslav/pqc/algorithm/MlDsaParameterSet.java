package io.mzaslav.pqc.algorithm;

import java.security.spec.NamedParameterSpec;

/**
 * ML-DSA parameter sets as defined in FIPS 204.
 * <p>
 * ML-DSA (Module-Lattice Digital Signature Algorithm), formerly known as
 * CRYSTALS-Dilithium, is a post-quantum digital signature scheme.
 * </p>
 * <p>
 * Each parameter set provides different security levels:
 * <ul>
 *   <li><b>ML-DSA-44</b> - NIST Category 2 (~SHA-256/AES-128 equivalent)</li>
 *   <li><b>ML-DSA-65</b> - NIST Category 3 (~AES-192 equivalent) - RECOMMENDED</li>
 *   <li><b>ML-DSA-87</b> - NIST Category 5 (~AES-256 equivalent)</li>
 * </ul>
 * </p>
 * <p>
 * <b>Note:</b> ML-DSA signatures are significantly larger than classical
 * signatures (e.g., RSA, ECDSA). Plan storage and bandwidth accordingly.
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public enum MlDsaParameterSet {
    
    /**
     * ML-DSA-44: NIST Category 2 security level.
     * <p>
     * Key and signature sizes:
     * <ul>
     *   <li>Public key: 1312 bytes</li>
     *   <li>Private key: 2560 bytes</li>
     *   <li>Signature: 2420 bytes</li>
     * </ul>
     * </p>
     */
    ML_DSA_44("ML-DSA-44", 1312, 2560, 2420),
    
    /**
     * ML-DSA-65: NIST Category 3 security level (RECOMMENDED).
     * <p>
     * This is the recommended parameter set for most applications.
     * Key and signature sizes:
     * <ul>
     *   <li>Public key: 1952 bytes</li>
     *   <li>Private key: 4032 bytes</li>
     *   <li>Signature: 3309 bytes</li>
     * </ul>
     * </p>
     */
    ML_DSA_65("ML-DSA-65", 1952, 4032, 3309),
    
    /**
     * ML-DSA-87: NIST Category 5 security level.
     * <p>
     * Maximum security level. Key and signature sizes:
     * <ul>
     *   <li>Public key: 2592 bytes</li>
     *   <li>Private key: 4896 bytes</li>
     *   <li>Signature: 4627 bytes</li>
     * </ul>
     * </p>
     */
    ML_DSA_87("ML-DSA-87", 2592, 4896, 4627);
    
    private final String parameterName;
    private final int publicKeySize;
    private final int privateKeySize;
    private final int signatureSize;
    
    MlDsaParameterSet(String parameterName, int publicKeySize, 
                      int privateKeySize, int signatureSize) {
        this.parameterName = parameterName;
        this.publicKeySize = publicKeySize;
        this.privateKeySize = privateKeySize;
        this.signatureSize = signatureSize;
    }
    
    /**
     * Returns the parameter name as used in Java Security API.
     *
     * @return the parameter set name (e.g., "ML-DSA-65")
     */
    public String getParameterName() {
        return parameterName;
    }
    
    /**
     * Creates a NamedParameterSpec for use with KeyPairGenerator.
     *
     * @return the NamedParameterSpec for this parameter set
     */
    public NamedParameterSpec toParameterSpec() {
        return new NamedParameterSpec(parameterName);
    }
    
    /**
     * Returns the public key size in bytes.
     *
     * @return public key size
     */
    public int getPublicKeySize() {
        return publicKeySize;
    }
    
    /**
     * Returns the private key size in bytes.
     *
     * @return private key size
     */
    public int getPrivateKeySize() {
        return privateKeySize;
    }
    
    /**
     * Returns the signature size in bytes.
     *
     * @return signature size
     */
    public int getSignatureSize() {
        return signatureSize;
    }
    
    /**
     * Returns the default (recommended) parameter set.
     *
     * @return ML_DSA_65 as the recommended default
     */
    public static MlDsaParameterSet getDefault() {
        return ML_DSA_65;
    }
}
