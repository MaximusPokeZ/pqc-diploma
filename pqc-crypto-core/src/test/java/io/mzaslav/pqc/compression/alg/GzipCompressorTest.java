package io.mzaslav.pqc.compression.alg;

import io.mzaslav.pqc.compression.CompressionAlgorithm;
import io.mzaslav.pqc.compression.DataCompressor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link GzipCompressor}.
 */
@DisplayName("GzipCompressor")
class GzipCompressorTest {

    private final DataCompressor compressor = new GzipCompressor();

    @Test
    @DisplayName("getAlgorithm returns GZIP")
    void getAlgorithmReturnsGzip() {
        assertThat(compressor.getAlgorithm()).isEqualTo(CompressionAlgorithm.GZIP);
    }

    @Test
    @DisplayName("compress and decompress round-trip preserves data")
    void compressDecompressRoundTrip() {
        byte[] original = "Hello, compressed world!".getBytes(StandardCharsets.UTF_8);
        byte[] compressed = compressor.compress(original);
        byte[] decompressed = compressor.decompress(compressed);
        assertThat(decompressed).isEqualTo(original);
    }

    @Test
    @DisplayName("compress reduces size for repetitive text")
    void compressReducesSizeForRepetitiveText() {
        String repeated = "ABCDEFGH ".repeat(1000);
        byte[] original = repeated.getBytes(StandardCharsets.UTF_8);
        byte[] compressed = compressor.compress(original);
        assertThat(compressed.length).isLessThan(original.length);
    }

    @Test
    @DisplayName("handles empty input")
    void handlesEmptyInput() {
        byte[] empty = new byte[0];
        byte[] compressed = compressor.compress(empty);
        byte[] decompressed = compressor.decompress(compressed);
        assertThat(decompressed).isEmpty();
    }

    @Test
    @DisplayName("handles large input")
    void handlesLargeInput() {
        byte[] large = new byte[100_000];
        for (int i = 0; i < large.length; i++) {
            large[i] = (byte) (i % 256);
        }
        byte[] compressed = compressor.compress(large);
        byte[] decompressed = compressor.decompress(compressed);
        assertThat(decompressed).isEqualTo(large);
    }
}
