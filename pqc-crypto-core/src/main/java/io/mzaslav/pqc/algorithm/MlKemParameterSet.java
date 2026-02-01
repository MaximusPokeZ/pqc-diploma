package io.mzaslav.pqc.algorithm;

import java.security.spec.NamedParameterSpec;

/**
 * ML-KEM parameter sets as defined in FIPS 203.
 * <p>
 * Each parameter set provides different security levels:
 * <ul>
 *   <li><b>ML-KEM-512</b> - NIST Category 1 (~AES-128 equivalent)</li>
 *   <li><b>ML-KEM-768</b> - NIST Category 3 (~AES-192 equivalent) - RECOMMENDED</li>
 *   <li><b>ML-KEM-1024</b> - NIST Category 5 (~AES-256 equivalent)</li>
 * </ul>
 * </p>
 * <p>
 * <b>Important:</b> Post-quantum algorithms produce significantly larger keys
 * and ciphertexts compared to classical algorithms. Choose the parameter set
 * based on your security requirements and performance constraints.
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public enum MlKemParameterSet {
    
    /**
     * ML-KEM-512: NIST Category 1 security level.
     * <p>
     * Key sizes:
     * <ul>
     *   <li>Public key: 800 bytes</li>
     *   <li>Private key: 1632 bytes</li>
     *   <li>Ciphertext: 768 bytes</li>
     *   <li>Shared secret: 32 bytes</li>
     * </ul>
     * </p>
     */
    ML_KEM_512("ML-KEM-512", 800, 1632, 768, 32),
    
    /**
     * ML-KEM-768: NIST Category 3 security level (RECOMMENDED).
     * <p>
     * This is the recommended parameter set for most applications.
     * Key sizes:
     * <ul>
     *   <li>Public key: 1184 bytes</li>
     *   <li>Private key: 2400 bytes</li>
     *   <li>Ciphertext: 1088 bytes</li>
     *   <li>Shared secret: 32 bytes</li>
     * </ul>
     * </p>
     */
    ML_KEM_768("ML-KEM-768", 1184, 2400, 1088, 32),
    
    /**
     * ML-KEM-1024: NIST Category 5 security level.
     * <p>
     * Maximum security level. Key sizes:
     * <ul>
     *   <li>Public key: 1568 bytes</li>
     *   <li>Private key: 3168 bytes</li>
     *   <li>Ciphertext: 1568 bytes</li>
     *   <li>Shared secret: 32 bytes</li>
     * </ul>
     * </p>
     */
    ML_KEM_1024("ML-KEM-1024", 1568, 3168, 1568, 32);
    
    private final String parameterName;
    private final int publicKeySize;
    private final int privateKeySize;
    private final int ciphertextSize;
    private final int sharedSecretSize;
    
    MlKemParameterSet(String parameterName, int publicKeySize, int privateKeySize,
                      int ciphertextSize, int sharedSecretSize) {
        this.parameterName = parameterName;
        this.publicKeySize = publicKeySize;
        this.privateKeySize = privateKeySize;
        this.ciphertextSize = ciphertextSize;
        this.sharedSecretSize = sharedSecretSize;
    }
    
    /**
     * Returns the parameter name as used in Java Security API.
     *
     * @return the parameter set name (e.g., "ML-KEM-768")
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
     * Returns the ciphertext (encapsulated key) size in bytes.
     *
     * @return ciphertext size
     */
    public int getCiphertextSize() {
        return ciphertextSize;
    }
    
    /**
     * Returns the shared secret size in bytes.
     *
     * @return shared secret size (always 32 bytes)
     */
    public int getSharedSecretSize() {
        return sharedSecretSize;
    }
    
    /**
     * Returns the default (recommended) parameter set.
     *
     * @return ML_KEM_768 as the recommended default
     */
    public static MlKemParameterSet getDefault() {
        return ML_KEM_768;
    }
}
