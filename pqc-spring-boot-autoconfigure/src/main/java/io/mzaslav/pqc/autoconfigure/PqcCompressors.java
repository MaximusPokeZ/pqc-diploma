package io.mzaslav.pqc.autoconfigure;

import io.mzaslav.pqc.compression.CompressionAlgorithm;
import io.mzaslav.pqc.compression.DataCompressor;
import io.mzaslav.pqc.compression.alg.FourierCompressor;
import io.mzaslav.pqc.compression.alg.GzipCompressor;
import io.mzaslav.pqc.compression.alg.Lz4Compressor;
import io.mzaslav.pqc.compression.alg.ZstdCompressor;

/**
 * Internal factory that maps a {@link CompressionAlgorithm} enum value to a
 * concrete {@link DataCompressor} instance for the auto-configuration to
 * attach to the {@code HybridEncryptor}.
 */
final class PqcCompressors {

    private PqcCompressors() {
    }

    /**
     * @param algorithm the configured compression algorithm
     * @return a fresh compressor, or {@code null} for {@link CompressionAlgorithm#NONE}
     */
    static DataCompressor create(CompressionAlgorithm algorithm) {
        if (algorithm == null || algorithm == CompressionAlgorithm.NONE) {
            return null;
        }
        return switch (algorithm) {
            case FOURIER -> new FourierCompressor();
            case GZIP -> new GzipCompressor();
            case ZSTD -> new ZstdCompressor();
            case LZ4 -> new Lz4Compressor();
            case NONE -> null;
        };
    }
}
