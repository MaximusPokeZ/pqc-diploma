package io.mzaslav.pqc.compression.alg;

import java.nio.ByteBuffer;

import com.github.luben.zstd.Zstd;
import io.mzaslav.pqc.compression.CompressionAlgorithm;
import io.mzaslav.pqc.compression.DataCompressor;

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

        // Считаем точный размер сырого буфера (до применения энтропийного кодера ZSTD)
        // На каждый блок: 64 байта метаданных Фурье (8 * 2 float) + размер самого блока (1 байт на residual)
        int rawBufferSize = 4 + (numBlocks * RETAINED_FREQUENCIES * 2 * 4) + data.length;
        ByteBuffer buffer = ByteBuffer.allocate(rawBufferSize);

        buffer.putInt(data.length); // Сохраняем оригинальную длину файла

        int offset = 0;
        double[] real = new double[BLOCK_SIZE];
        double[] imag = new double[BLOCK_SIZE];

        while (offset < data.length) {
            int currentBlockSize = Math.min(BLOCK_SIZE, data.length - offset);

            // Подготовка данных (заполнение нулями "хвоста" при необходимости)
            for (int i = 0; i < BLOCK_SIZE; i++) {
                real[i] = (i < currentBlockSize) ? (data[offset + i] & 0xFF) : 0;
                imag[i] = 0;
            }

            // Прямое БПФ
            fft(real, imag, false);

            // Сохраняем главные гармоники (Пишем float в буфер)
            for (int i = 0; i < RETAINED_FREQUENCIES; i++) {
                buffer.putFloat((float) real[i]);
                buffer.putFloat((float) imag[i]);
            }

            // Обнуляем "шум" (высокие частоты)
            for (int i = RETAINED_FREQUENCIES; i < BLOCK_SIZE; i++) {
                real[i] = 0;
                imag[i] = 0;
            }

            // Обратное БПФ
            fft(real, imag, true);

            // Вычисляем Residuals используем 8-битную модулярную арифметику
            for (int i = 0; i < currentBlockSize; i++) {
                int originalByte = data[offset + i] & 0xFF;
                int predictedByte = (int) Math.round(real[i]);

                // (byte) автоматически делает циклическое обрезание битов,
                // поэтому нам не нужно обрабатывать overflow (выход за пределы -128..127)
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

        // 1. Быстро снимаем промежуточный слой ZSTD
        long decompressedSize = Zstd.getFrameContentSize(compressedData);
        if (decompressedSize <= 0 || decompressedSize > 100_000_000) {
            throw new RuntimeException("Invalid Fourier-ZSTD frame");
        }
        byte[] rawBuffer = Zstd.decompress(compressedData, (int) decompressedSize);
        ByteBuffer buffer = ByteBuffer.wrap(rawBuffer);

        // 2. Читаем размер оригинального документа
        int originalLength = buffer.getInt();
        byte[] result = new byte[originalLength];

        int offset = 0;
        double[] real = new double[BLOCK_SIZE];
        double[] imag = new double[BLOCK_SIZE];

        while (offset < originalLength) {
            int currentBlockSize = Math.min(BLOCK_SIZE, originalLength - offset);

            // 3. Читаем сохраненные 8 главных гармоник
            for (int i = 0; i < BLOCK_SIZE; i++) {
                if (i < RETAINED_FREQUENCIES) {
                    real[i] = buffer.getFloat();
                    imag[i] = buffer.getFloat();
                } else {
                    real[i] = 0;
                    imag[i] = 0;
                }
            }

            // 4. Обратное БПФ строит предсказанный сигнал
            fft(real, imag, true);

            // 5. Читаем Residuals и восстанавливаем оригинальный байт
            for (int i = 0; i < currentBlockSize; i++) {
                byte residual = buffer.get();
                int predictedByte = (int) Math.round(real[i]);

                // Обратная математическая магия: сложение с обрезанием восстановит байт
                result[offset + i] = (byte) (predictedByte + residual);
            }

            offset += currentBlockSize;
        }

        return result;
    }

    // метод алгоритма Кули-Тьюки Radix-2
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