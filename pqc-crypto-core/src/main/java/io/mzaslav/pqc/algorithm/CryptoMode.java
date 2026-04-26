package io.mzaslav.pqc.algorithm;

/**
 * Operating mode for hybrid cryptographic primitives.
 * <p>
 * Selects whether classical, post-quantum, or both algorithm families are used.
 *
 * @author mzaslav
 * @since 1.0
 */
public enum CryptoMode {
    /** Combine a classical algorithm with a PQC algorithm (recommended). */
    HYBRID,
    /** Use only the post-quantum algorithm. */
    PQC_ONLY,
    /** Use only the classical algorithm (legacy interop, no quantum resistance). */
    CLASSICAL_ONLY
}
