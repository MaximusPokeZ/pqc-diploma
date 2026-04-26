package io.mzaslav.pqc.compression.alg;

import java.nio.ByteBuffer;

import com.github.luben.zstd.Zstd;
import io.mzaslav.pqc.compression.CompressionAlgorithm;
import io.mzaslav.pqc.compression.DataCompressor;

/**
 * Experimental Fourier-domain residual compressor.
 * <p>
 * Splits the input into 1024-byte blocks, runs a Cooley-Tukey radix-2 FFT and
 * keeps the {@value #RETAINED_FREQUENCIES} dominant harmonics; the residual
 * between the original bytes and the inverse-FFT prediction is then fed
 * through Zstd entropy coding. Designed for signal-like data where most
 * energy concentrates in a few frequencies; on generic data it is usually
 * out-performed by {@link ZstdCompressor}.
 *
 * @author mzaslav
 * @since 1.0
 */
public class FourierCompressor implements DataCompressor {

    private static final int BLOCK_SIZE = 1024;
    private static final int RETAINED_FREQUENCIES = 8;

    @Override
    public CompressionAlgorithm getAlgorithm() {
        return CompressionAlgorithm.FOURIER;
    }

    @Override
    public byte[] compress(byte[] data) {
        if (data == null || data.length == 0) return data;

        int numBlocks = (int) Math.ceil((double) data.length / BLOCK_SIZE);

        // Raw buffer size before entropy coding: 4 bytes for original length
        // + per-block: RETAINED_FREQUENCIES * 2 floats (Fourier metadata) + 1 residual byte per data byte.
        int rawBufferSize = 4 + (numBlocks * RETAINED_FREQUENCIES * 2 * 4) + data.length;
        ByteBuffer buffer = ByteBuffer.allocate(rawBufferSize);

        buffer.putInt(data.length);

        int offset = 0;
        double[] real = new double[BLOCK_SIZE];
        double[] imag = new double[BLOCK_SIZE];

        while (offset < data.length) {
            int currentBlockSize = Math.min(BLOCK_SIZE, data.length - offset);

            // Load block, zero-pad the tail when needed.
            for (int i = 0; i < BLOCK_SIZE; i++) {
                real[i] = (i < currentBlockSize) ? (data[offset + i] & 0xFF) : 0;
                imag[i] = 0;
            }

            // Forward FFT
            fft(real, imag, false);

            // Persist the dominant harmonics as floats.
            for (int i = 0; i < RETAINED_FREQUENCIES; i++) {
                buffer.putFloat((float) real[i]);
                buffer.putFloat((float) imag[i]);
            }

            // Zero out the high-frequency "noise" coefficients.
            for (int i = RETAINED_FREQUENCIES; i < BLOCK_SIZE; i++) {
                real[i] = 0;
                imag[i] = 0;
            }

            // Inverse FFT to obtain the predicted signal.
            fft(real, imag, true);

            // Store residuals in 8-bit modular arithmetic; (byte) cast handles
            // wrap-around so explicit overflow handling is unnecessary.
            for (int i = 0; i < currentBlockSize; i++) {
                int originalByte = data[offset + i] & 0xFF;
                int predictedByte = (int) Math.round(real[i]);
                byte residual = (byte) (originalByte - predictedByte);
                buffer.put(residual);
            }

            offset += currentBlockSize;
        }

        return Zstd.compress(buffer.array(), 3);
    }

    @Override
    public byte[] decompress(byte[] compressedData) {
        if (compressedData == null || compressedData.length == 0) return compressedData;

        // 1. Strip the outer Zstd frame.
        long decompressedSize = Zstd.getFrameContentSize(compressedData);
        if (decompressedSize <= 0 || decompressedSize > 100_000_000) {
            throw new RuntimeException("Invalid Fourier-ZSTD frame");
        }
        byte[] rawBuffer = Zstd.decompress(compressedData, (int) decompressedSize);
        ByteBuffer buffer = ByteBuffer.wrap(rawBuffer);

        // 2. Read original payload length.
        int originalLength = buffer.getInt();
        byte[] result = new byte[originalLength];

        int offset = 0;
        double[] real = new double[BLOCK_SIZE];
        double[] imag = new double[BLOCK_SIZE];

        while (offset < originalLength) {
            int currentBlockSize = Math.min(BLOCK_SIZE, originalLength - offset);

            // 3. Read the persisted dominant harmonics.
            for (int i = 0; i < BLOCK_SIZE; i++) {
                if (i < RETAINED_FREQUENCIES) {
                    real[i] = buffer.getFloat();
                    imag[i] = buffer.getFloat();
                } else {
                    real[i] = 0;
                    imag[i] = 0;
                }
            }

            // 4. Inverse FFT yields the predicted signal.
            fft(real, imag, true);

            // 5. Combine prediction + residual to recover each original byte.
            for (int i = 0; i < currentBlockSize; i++) {
                byte residual = buffer.get();
                int predictedByte = (int) Math.round(real[i]);
                result[offset + i] = (byte) (predictedByte + residual);
            }

            offset += currentBlockSize;
        }

        return result;
    }

    // Cooley-Tukey radix-2 FFT.
    private void fft(double[] real, double[] imag, boolean inverse) {
        int n = real.length;
        if (n == 0) return;

        int shift = 1 + Integer.numberOfLeadingZeros(n);
        for (int i = 0; i < n; i++) {
            int j = Integer.reverse(i) >>> shift;
            if (j > i) {
                double tempReal = real[j];
                double tempImag = imag[j];
                real[j] = real[i];
                imag[j] = imag[i];
                real[i] = tempReal;
                imag[i] = tempImag;
            }
        }

        for (int size = 2; size <= n; size *= 2) {
            int halfSize = size / 2;
            double angle = (inverse ? 2 * Math.PI : -2 * Math.PI) / size;
            double wRealPrincipal = Math.cos(angle);
            double wImagPrincipal = Math.sin(angle);

            for (int i = 0; i < n; i += size) {
                double wReal = 1.0;
                double wImag = 0.0;

                for (int j = 0; j < halfSize; j++) {
                    int k = i + j;
                    int l = i + j + halfSize;

                    double tReal = real[l] * wReal - imag[l] * wImag;
                    double tImag = real[l] * wImag + imag[l] * wReal;

                    real[l] = real[k] - tReal;
                    imag[l] = imag[k] - tImag;
                    real[k] += tReal;
                    imag[k] += tImag;

                    double nextWReal = wReal * wRealPrincipal - wImag * wImagPrincipal;
                    double nextWImag = wReal * wImagPrincipal + wImag * wRealPrincipal;
                    wReal = nextWReal;
                    wImag = nextWImag;
                }
            }
        }

        if (inverse) {
            for (int i = 0; i < n; i++) {
                real[i] /= n;
                imag[i] /= n;
            }
        }
    }

    @Override
    public String toString() {
        return getAlgorithm().name();
    }
}