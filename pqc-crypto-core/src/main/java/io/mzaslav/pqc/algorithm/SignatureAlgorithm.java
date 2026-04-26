package io.mzaslav.pqc.algorithm;

/**
 * High-level signature scheme identifier produced by a {@code SignatureProvider}.
 *
 * @author mzaslav
 * @since 1.0
 */
public enum SignatureAlgorithm {
    /** Post-quantum ML-DSA (FIPS 204). */
    ML_DSA("ML-DSA"),
    /** Pure classical scheme (Ed25519, ECDSA P-256 or RSA-2048). */
    CLASSICAL("CLASSICAL"),
    /** Hybrid scheme combining a classical signature with ML-DSA. */
    HYBRID("CLASSICAL-ML-DSA");

    private final String algorithmName;

    SignatureAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * @return human-readable name of the scheme
     */
    public String getAlgorithmName() {
        return algorithmName;
    }
}
