package io.mzaslav.pqc.compression;

/**
 * Pluggable data compressor used to shrink plaintext before encryption.
 * <p>
 * Implementations are stateless and must be safe for concurrent use. The
 * algorithm identifier travels in the {@link io.mzaslav.pqc.hybrid.EncryptedMessage}
 * header so the decryptor can pick the matching decompressor.
 *
 * @author mzaslav
 * @since 1.0
 */
public interface DataCompressor {

    /**
     * @return the algorithm tag stored in the encrypted message header
     */
    CompressionAlgorithm getAlgorithm();

    /**
     * Compresses a byte payload.
     *
     * @param data raw bytes
     * @return compressed bytes (implementation-specific framing)
     */
    byte[] compress(byte[] data);

    /**
     * Decompresses bytes produced by {@link #compress(byte[])}.
     *
     * @param compressedData compressed input
     * @return the original plaintext bytes
     */
    byte[] decompress(byte[] compressedData);
}
