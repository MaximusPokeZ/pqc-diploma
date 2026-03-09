package io.mzaslav.pqc.compression;

public enum CompressionAlgorithm {

    NONE((byte) 0x00),
    FOURIER((byte) 0x01),
    GZIP((byte) 0x02),
    ZSTD((byte) 0x03),
    LZ4((byte) 0x04);

    private final byte id;

    CompressionAlgorithm(byte id) {
        this.id = id;
    }

    public byte getId() {
        return id;
    }

    public static CompressionAlgorithm fromId(byte id) {
        for (CompressionAlgorithm algorithm : values()) {
            if (algorithm.id == id) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unknown compression algorithm id: " + id);
    }
}
