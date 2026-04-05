package io.mzaslav.pqc.autoconfigure;

import io.mzaslav.pqc.compression.CompressionAlgorithm;
import io.mzaslav.pqc.compression.DataCompressor;
import io.mzaslav.pqc.compression.alg.FourierCompressor;
import io.mzaslav.pqc.compression.alg.GzipCompressor;
import io.mzaslav.pqc.compression.alg.Lz4Compressor;
import io.mzaslav.pqc.compression.alg.ZstdCompressor;

final class PqcCompressors {

    private PqcCompressors() {
    }

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
