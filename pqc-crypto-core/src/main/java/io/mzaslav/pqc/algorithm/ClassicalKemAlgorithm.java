package io.mzaslav.pqc.algorithm;

/**
 * Supported classical Key Encapsulation Mechanism algorithms.
 *
 * @author mzaslav
 * @since 1.0
 */
public enum ClassicalKemAlgorithm {
    /** X25519 elliptic-curve Diffie-Hellman (RFC 7748). Fast and compact. */
    X25519,
    /** NIST P-256 (secp256r1) ECDH. Required by some compliance regimes. */
    SECP256R1
}
