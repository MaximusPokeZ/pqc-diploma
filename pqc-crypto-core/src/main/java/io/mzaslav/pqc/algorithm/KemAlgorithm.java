package io.mzaslav.pqc.algorithm;

/**
 * Enumeration of supported Key Encapsulation Mechanism (KEM) algorithms.
 * <p>
 * This library supports:
 * <ul>
 *   <li><b>ML-KEM</b> (FIPS 203) - Post-quantum KEM based on Module-LWE</li>
 *   <li><b>X25519</b> - Classical elliptic curve Diffie-Hellman</li>
 *   <li><b>HYBRID</b> - Combination of X25519 + ML-KEM for defense-in-depth</li>
 * </ul>
 * </p>
 * <p>
 * The hybrid approach protects against "Harvest Now, Decrypt Later" attacks
 * by combining classical and post-quantum algorithms.
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public enum KemAlgorithm {
    
    /**
     * ML-KEM (Module-Lattice Key Encapsulation Mechanism).
     * <p>
     * Formerly known as CRYSTALS-Kyber. Standardized in FIPS 203.
     * Provides post-quantum security based on the hardness of the
     * Module Learning With Errors (M-LWE) problem.
     * </p>
     */
    ML_KEM("ML-KEM"),
    
    /**
     * X25519 Elliptic Curve Diffie-Hellman.
     * <p>
     * Classical ECDH using Curve25519. Provides fast key agreement
     * with 128-bit security level against classical computers.
     * </p>
     */
    X25519("X25519"),
    
    /**
     * Hybrid KEM combining X25519 and ML-KEM.
     * <p>
     * Provides defense-in-depth by requiring an attacker to break
     * both classical and post-quantum algorithms.
     * The shared secrets are combined using HKDF with SHA3-256.
     * </p>
     */
    HYBRID("X25519-ML-KEM");
    
    private final String algorithmName;
    
    KemAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }
    
    /**
     * Returns the algorithm name as used in JCA/JCE.
     *
     * @return the algorithm name
     */
    public String getAlgorithmName() {
        return algorithmName;
    }
}
