package io.mzaslav.pqc.algorithm;

/**
 * Supported classical digital signature algorithms.
 *
 * @author mzaslav
 * @since 1.0
 */
public enum ClassicalSigAlgorithm {
    /** Edwards-curve Ed25519 (RFC 8032). Fast and compact (~64-byte signatures). */
    ED25519,
    /** ECDSA over NIST P-256 with SHA-256. */
    ECDSA_P256,
    /** RSA-2048 with SHA-256 (PKCS#1 v1.5). Largest signatures and slowest. */
    RSA_2048
}
