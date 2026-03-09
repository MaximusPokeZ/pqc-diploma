package io.mzaslav.pqc.compression.alg;

import com.github.luben.zstd.Zstd;
import io.mzaslav.pqc.compression.CompressionAlgorithm;
import io.mzaslav.pqc.compression.DataCompressor;
import io.mzaslav.pqc.exception.EncryptionException;

public class ZstdCompressor implements DataCompressor {

    // Уровень сжатия (от 1 до 22). 3 - это дефолт, идеальный баланс скорости и размера.
    private static final int COMPRESSION_LEVEL = 3;

    @Override
    public CompressionAlgorithm getAlgorithm() {
        return CompressionAlgorithm.ZSTD;
    }

    @Override
    public byte[] compress(byte[] data) {
        if (data == null || data.length == 0) {
            return data;
        }
        try {
            return Zstd.compress(data, COMPRESSION_LEVEL);
        } catch (Exception e) {
            throw new RuntimeException("ZSTD compression failed", e);
        }
    }

    @Override
    public byte[] decompress(byte[] compressedData) {
        if (compressedData == null || compressedData.length == 0) {
            return compressedData;
        }
        try {
            long decompressedSize = Zstd.getFrameContentSize(compressedData);

            if (decompressedSize == -1) { // Zstd.CONTENTSIZE_UNKNOWN
                throw new EncryptionException("ZSTD frame content size is unknown");
            }
            if (decompressedSize == -2) { // Zstd.CONTENTSIZE_ERROR
                throw new EncryptionException("ZSTD frame content size error: corrupted or truncated data");
            }

            if (decompressedSize > Integer.MAX_VALUE) {
                throw new EncryptionException("Decompressed data exceeds maximum byte array size (2GB)");
            }

            return Zstd.decompress(compressedData, (int) decompressedSize);
        } catch (Exception e) {
            throw new RuntimeException("ZSTD decompression failed", e);
        }
    }

    @Override
    public String toString() {
        return getAlgorithm().name();
    }
}