package io.mzaslav.pqc.compression;

/**
 * Identifier of the compression algorithm applied to plaintext before encryption.
 * <p>
 * The 1-byte {@link #getId() id} is written into the {@code EncryptedMessage}
 * header so that the receiving side can pick a matching {@link DataCompressor}.
 *
 * @author mzaslav
 * @since 1.0
 */
public enum CompressionAlgorithm {

    /** No compression. */
    NONE((byte) 0x00),
    /** Custom Fourier-domain residual coder followed by ZSTD entropy coding. */
    FOURIER((byte) 0x01),
    /** Standard GZIP (RFC 1952). */
    GZIP((byte) 0x02),
    /** ZStandard (Zstd) - high ratio, good speed. */
    ZSTD((byte) 0x03),
    /** LZ4 - fastest decompression, lowest ratio. */
    LZ4((byte) 0x04);

    private final byte id;

    CompressionAlgorithm(byte id) {
        this.id = id;
    }

    /**
     * @return wire-format identifier byte
     */
    public byte getId() {
        return id;
    }

    /**
     * Resolves an algorithm from its wire-format id.
     *
     * @param id the byte read from the message header
     * @return the matching {@link CompressionAlgorithm}
     * @throws IllegalArgumentException if the id is unknown
     */
    public static CompressionAlgorithm fromId(byte id) {
        for (CompressionAlgorithm algorithm : values()) {
            if (algorithm.id == id) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unknown compression algorithm id: " + id);
    }
}
