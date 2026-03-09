package io.mzaslav.pqc.compression;

public interface DataCompressor {
    CompressionAlgorithm getAlgorithm();

    byte[] compress(byte[] data);

    byte[] decompress(byte[] compressedData);
}
