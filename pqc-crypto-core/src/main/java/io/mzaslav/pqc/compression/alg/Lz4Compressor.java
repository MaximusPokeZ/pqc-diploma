package io.mzaslav.pqc.compression.alg;

import io.mzaslav.pqc.compression.CompressionAlgorithm;
import io.mzaslav.pqc.compression.DataCompressor;
import io.mzaslav.pqc.exception.EncryptionException;
import net.jpountz.lz4.LZ4Compressor;
import net.jpountz.lz4.LZ4Factory;
import net.jpountz.lz4.LZ4FastDecompressor;

public class Lz4Compressor implements DataCompressor {

    // Получаем самую быструю реализацию (JNI, если доступна, иначе Pure Java)
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

        // Массив для результата: 4 байта на длину + сжатые данные
        byte[] compressed = new byte[4 + maxCompressedLength];

        // 1. Записываем оригинальный размер в первые 4 байта (Big-Endian)
        int uncompressedLength = data.length;
        compressed[0] = (byte) (uncompressedLength >>> 24);
        compressed[1] = (byte) (uncompressedLength >>> 16);
        compressed[2] = (byte) (uncompressedLength >>> 8);
        compressed[3] = (byte) uncompressedLength;

        // 2. Сжимаем (пишем начиная со смещения 4)
        int compressedLength = compressor.compress(data, 0, uncompressedLength, compressed, 4, maxCompressedLength);

        // 3. Копируем в массив точного размера, чтобы не передавать хвост из нулей
        byte[] finalResult = new byte[4 + compressedLength];
        System.arraycopy(compressed, 0, finalResult, 0, 4 + compressedLength);

        return finalResult;
    }

    @Override
    public byte[] decompress(byte[] compressedData) {
        if (compressedData == null || compressedData.length == 0) {
            return compressedData;
        }

        // Защита от битых данных
        if (compressedData.length < 4) {
            throw new EncryptionException("Invalid LZ4 data: missing length header");
        }

        // 1. Читаем оригинальный размер из первых 4 байт
        int uncompressedLength = ((compressedData[0] & 0xFF) << 24) |
                ((compressedData[1] & 0xFF) << 16) |
                ((compressedData[2] & 0xFF) << 8) |
                (compressedData[3] & 0xFF);

        // Защита целостности
        if (uncompressedLength < 0 || uncompressedLength > 100_000_000) { // Лимит 100 МБ для защиты от Zip-бомб
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