package io.mzaslav.pqc.compression.alg;

import io.mzaslav.pqc.compression.CompressionAlgorithm;
import io.mzaslav.pqc.compression.DataCompressor;
import io.mzaslav.pqc.exception.EncryptionException;
import net.jpountz.lz4.LZ4Compressor;
import net.jpountz.lz4.LZ4Factory;
import net.jpountz.lz4.LZ4FastDecompressor;

/**
 * LZ4 compressor optimised for speed.
 * <p>
 * The fastest of the supported algorithms; chosen when low latency is more
 * important than compression ratio. Output framing is {@code [4-byte BE
 * uncompressed length] || [LZ4 compressed bytes]}.
 *
 * @author mzaslav
 * @since 1.0
 */
public class Lz4Compressor implements DataCompressor {

    // Pick the fastest implementation available (JNI when present, otherwise pure Java).
    private static final LZ4Factory factory = LZ4Factory.fastestInstance();

    @Override
    public CompressionAlgorithm getAlgorithm() {
        return CompressionAlgorithm.LZ4;
    }

    @Override
    public byte[] compress(byte[] data) {
        if (data == null || data.length == 0) {
            return data;
        }

        LZ4Compressor compressor = factory.fastCompressor();
        int maxCompressedLength = compressor.maxCompressedLength(data.length);

        // Layout: 4-byte big-endian uncompressed length || LZ4 payload.
        byte[] compressed = new byte[4 + maxCompressedLength];

        int uncompressedLength = data.length;
        compressed[0] = (byte) (uncompressedLength >>> 24);
        compressed[1] = (byte) (uncompressedLength >>> 16);
        compressed[2] = (byte) (uncompressedLength >>> 8);
        compressed[3] = (byte) uncompressedLength;

        int compressedLength = compressor.compress(data, 0, uncompressedLength, compressed, 4, maxCompressedLength);

        // Copy into a tight array so we don't ship a zero-padded tail.
        byte[] finalResult = new byte[4 + compressedLength];
        System.arraycopy(compressed, 0, finalResult, 0, 4 + compressedLength);

        return finalResult;
    }

    @Override
    public byte[] decompress(byte[] compressedData) {
        if (compressedData == null || compressedData.length == 0) {
            return compressedData;
        }

        if (compressedData.length < 4) {
            throw new EncryptionException("Invalid LZ4 data: missing length header");
        }

        int uncompressedLength = ((compressedData[0] & 0xFF) << 24) |
                ((compressedData[1] & 0xFF) << 16) |
                ((compressedData[2] & 0xFF) << 8) |
                (compressedData[3] & 0xFF);

        // 100 MB cap guards against zip-bomb-style attacks.
        if (uncompressedLength < 0 || uncompressedLength > 100_000_000) {
            throw new EncryptionException("Invalid LZ4 data: corrupted uncompressed length");
        }

        byte[] restored = new byte[uncompressedLength];
        LZ4FastDecompressor decompressor = factory.fastDecompressor();

        try {
            decompressor.decompress(compressedData, 4, restored, 0, uncompressedLength);
            return restored;
        } catch (Exception e) {
            throw new EncryptionException("LZ4 decompression failed: data is corrupted", e);
        }
    }

    @Override
    public String toString() {
        return getAlgorithm().name();
    }
}