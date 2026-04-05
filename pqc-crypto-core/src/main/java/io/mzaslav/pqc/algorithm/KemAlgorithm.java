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
    ML_KEM("ML-KEM"),
    X25519("X25519"),
    SECP256R1("secp256r1"),
    HYBRID("HYBRID");

    private final String algorithmName;

    KemAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }
}
