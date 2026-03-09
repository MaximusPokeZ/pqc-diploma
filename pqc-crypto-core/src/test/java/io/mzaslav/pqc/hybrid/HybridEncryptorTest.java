package io.mzaslav.pqc.hybrid;

import io.mzaslav.pqc.algorithm.KemAlgorithm;
import io.mzaslav.pqc.algorithm.MlKemParameterSet;
import io.mzaslav.pqc.compression.CompressionAlgorithm;
import io.mzaslav.pqc.compression.DataCompressor;
import io.mzaslav.pqc.compression.alg.FourierCompressor;
import io.mzaslav.pqc.compression.alg.GzipCompressor;
import io.mzaslav.pqc.compression.alg.Lz4Compressor;
import io.mzaslav.pqc.compression.alg.ZstdCompressor;
import io.mzaslav.pqc.exception.EncryptionException;
import io.mzaslav.pqc.kem.KemKeyPair;
import io.mzaslav.pqc.util.SecureBytes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link HybridEncryptor}.
 * 
 * These tests verify the high-level hybrid encryption API that combines
 * X25519 + ML-KEM key encapsulation with AES-GCM symmetric encryption.
 */
@DisplayName("HybridEncryptor")
class HybridEncryptorTest {

    @Nested
    @DisplayName("Factory methods")
    class FactoryMethodsTest {

        @Test
        @DisplayName("create() should use hybrid X25519+ML-KEM-768")
        void createShouldUseHybrid() {
            HybridEncryptor encryptor = HybridEncryptor.create();
            
            assertThat(encryptor.getAlgorithm()).isEqualTo(KemAlgorithm.HYBRID);
            assertThat(encryptor.getMlKemParameterSet()).isEqualTo(MlKemParameterSet.ML_KEM_768);
        }

        @ParameterizedTest
        @EnumSource(MlKemParameterSet.class)
        @DisplayName("should support all ML-KEM parameter sets")
        void shouldSupportAllParameterSets(MlKemParameterSet parameterSet) {
            HybridEncryptor encryptor = HybridEncryptor.create(parameterSet);
            
            assertThat(encryptor.getAlgorithm()).isEqualTo(KemAlgorithm.HYBRID);
            assertThat(encryptor.getMlKemParameterSet()).isEqualTo(parameterSet);
        }

        @Test
        @DisplayName("createPqcOnly() should use only ML-KEM")
        void createPqcOnlyShouldUseMlKem() {
            HybridEncryptor encryptor = HybridEncryptor.createPqcOnly(MlKemParameterSet.ML_KEM_768);
            
            assertThat(encryptor.getAlgorithm()).isEqualTo(KemAlgorithm.ML_KEM);
        }

        @Test
        @DisplayName("createClassicalOnly() should use only X25519")
        void createClassicalOnlyShouldUseX25519() {
            HybridEncryptor encryptor = HybridEncryptor.createClassicalOnly();
            
            assertThat(encryptor.getAlgorithm()).isEqualTo(KemAlgorithm.X25519);
            assertThat(encryptor.getMlKemParameterSet()).isNull();
        }
    }

    @Nested
    @DisplayName("Encryption and decryption")
    class EncryptionTest {

        @Test
        @DisplayName("should encrypt and decrypt message")
        void shouldEncryptAndDecrypt() {
            HybridEncryptor encryptor = HybridEncryptor.create();
            byte[] plaintext = "Hello, Post-Quantum World!".getBytes(StandardCharsets.UTF_8);
            
            try (KemKeyPair keyPair = encryptor.generateKeyPair()) {
                EncryptedMessage encrypted = encryptor.encrypt(
                    keyPair.getEncodedPublicKey(), plaintext);
                
                assertThat(encrypted.getAlgorithm()).isEqualTo(KemAlgorithm.HYBRID);
                assertThat(encrypted.getEncapsulatedKey()).isNotEmpty();
                assertThat(encrypted.getCiphertext()).isNotEmpty();
                
                byte[] decrypted = encryptor.decrypt(keyPair, encrypted);
                
                assertThat(decrypted).isEqualTo(plaintext);
            }
        }

        @Test
        @DisplayName("should encrypt with associated data")
        void shouldEncryptWithAAD() {
            HybridEncryptor encryptor = HybridEncryptor.create();
            byte[] plaintext = "Secret message".getBytes(StandardCharsets.UTF_8);
            byte[] aad = "header info".getBytes(StandardCharsets.UTF_8);
            
            try (KemKeyPair keyPair = encryptor.generateKeyPair()) {
                EncryptedMessage encrypted = encryptor.encrypt(
                    keyPair.getEncodedPublicKey(), plaintext, aad);
                
                byte[] decrypted = encryptor.decrypt(keyPair, encrypted, aad);
                
                assertThat(decrypted).isEqualTo(plaintext);
            }
        }

        @Test
        @DisplayName("should fail decryption with wrong AAD")
        void shouldFailWithWrongAAD() {
            HybridEncryptor encryptor = HybridEncryptor.create();
            byte[] plaintext = "Secret".getBytes(StandardCharsets.UTF_8);
            byte[] correctAad = "correct".getBytes(StandardCharsets.UTF_8);
            byte[] wrongAad = "wrong".getBytes(StandardCharsets.UTF_8);
            
            try (KemKeyPair keyPair = encryptor.generateKeyPair()) {
                EncryptedMessage encrypted = encryptor.encrypt(
                    keyPair.getEncodedPublicKey(), plaintext, correctAad);
                
                assertThatThrownBy(() -> encryptor.decrypt(keyPair, encrypted, wrongAad))
                    .isInstanceOf(EncryptionException.class);
            }
        }

        @ParameterizedTest
        @EnumSource(MlKemParameterSet.class)
        @DisplayName("should work with all ML-KEM parameter sets")
        void shouldWorkWithAllParameterSets(MlKemParameterSet parameterSet) {
            HybridEncryptor encryptor = HybridEncryptor.create(parameterSet);
            byte[] plaintext = "Test message".getBytes(StandardCharsets.UTF_8);
            
            try (KemKeyPair keyPair = encryptor.generateKeyPair()) {
                EncryptedMessage encrypted = encryptor.encrypt(
                    keyPair.getEncodedPublicKey(), plaintext);
                
                byte[] decrypted = encryptor.decrypt(keyPair, encrypted);
                
                assertThat(decrypted).isEqualTo(plaintext);
            }
        }

        @Test
        @DisplayName("should handle empty plaintext")
        void shouldHandleEmptyPlaintext() {
            HybridEncryptor encryptor = HybridEncryptor.create();
            byte[] plaintext = new byte[0];
            
            try (KemKeyPair keyPair = encryptor.generateKeyPair()) {
                EncryptedMessage encrypted = encryptor.encrypt(
                    keyPair.getEncodedPublicKey(), plaintext);
                
                byte[] decrypted = encryptor.decrypt(keyPair, encrypted);
                
                assertThat(decrypted).isEmpty();
            }
        }

        @Test
        @DisplayName("should handle large plaintext")
        void shouldHandleLargePlaintext() {
            HybridEncryptor encryptor = HybridEncryptor.create();
            byte[] plaintext = SecureBytes.randomBytes(100_000);
            
            try (KemKeyPair keyPair = encryptor.generateKeyPair()) {
                EncryptedMessage encrypted = encryptor.encrypt(
                    keyPair.getEncodedPublicKey(), plaintext);
                
                byte[] decrypted = encryptor.decrypt(keyPair, encrypted);
                
                assertThat(decrypted).isEqualTo(plaintext);
            }
        }
    }

    @Nested
    @DisplayName("Serialization")
    class SerializationTest {

        @Test
        @DisplayName("should serialize and deserialize encrypted message")
        void shouldSerializeAndDeserialize() {
            HybridEncryptor encryptor = HybridEncryptor.create();
            byte[] plaintext = "Test".getBytes(StandardCharsets.UTF_8);
            
            try (KemKeyPair keyPair = encryptor.generateKeyPair()) {
                EncryptedMessage encrypted = encryptor.encrypt(
                    keyPair.getEncodedPublicKey(), plaintext);
                
                // Serialize
                byte[] serialized = encrypted.toBytes();
                
                // Deserialize
                EncryptedMessage restored = EncryptedMessage.fromBytes(serialized);
                
                assertThat(restored.getAlgorithm()).isEqualTo(encrypted.getAlgorithm());
                assertThat(restored.getEncapsulatedKey()).isEqualTo(encrypted.getEncapsulatedKey());
                assertThat(restored.getCiphertext()).isEqualTo(encrypted.getCiphertext());
                
                // Decrypt restored message
                byte[] decrypted = encryptor.decrypt(keyPair, restored);
                assertThat(decrypted).isEqualTo(plaintext);
            }
        }

        @Test
        @DisplayName("should decrypt from serialized bytes")
        void shouldDecryptFromBytes() {
            HybridEncryptor encryptor = HybridEncryptor.create();
            byte[] plaintext = "Test".getBytes(StandardCharsets.UTF_8);
            
            try (KemKeyPair keyPair = encryptor.generateKeyPair()) {
                EncryptedMessage encrypted = encryptor.encrypt(
                    keyPair.getEncodedPublicKey(), plaintext);
                
                byte[] serialized = encrypted.toBytes();
                byte[] decrypted = encryptor.decrypt(keyPair, serialized);
                
                assertThat(decrypted).isEqualTo(plaintext);
            }
        }
    }

    @Nested
    @DisplayName("Security properties")
    class SecurityPropertiesTest {

        @Test
        @DisplayName("should fail decryption with wrong key")
        void shouldFailWithWrongKey() {
            HybridEncryptor encryptor = HybridEncryptor.create();
            byte[] plaintext = "Secret".getBytes(StandardCharsets.UTF_8);
            
            try (KemKeyPair correctKey = encryptor.generateKeyPair();
                 KemKeyPair wrongKey = encryptor.generateKeyPair()) {
                
                EncryptedMessage encrypted = encryptor.encrypt(
                    correctKey.getEncodedPublicKey(), plaintext);
                
                // Try to decrypt with wrong key
                assertThatThrownBy(() -> encryptor.decrypt(wrongKey, encrypted))
                    .isInstanceOf(EncryptionException.class);
            }
        }

        @Test
        @DisplayName("should produce different ciphertexts for same plaintext")
        void shouldProduceDifferentCiphertexts() {
            HybridEncryptor encryptor = HybridEncryptor.create();
            byte[] plaintext = "Same message".getBytes(StandardCharsets.UTF_8);
            
            try (KemKeyPair keyPair = encryptor.generateKeyPair()) {
                EncryptedMessage e1 = encryptor.encrypt(keyPair.getEncodedPublicKey(), plaintext);
                EncryptedMessage e2 = encryptor.encrypt(keyPair.getEncodedPublicKey(), plaintext);
                
                // Encapsulated keys should differ (different KEM randomness)
                assertThat(e1.getEncapsulatedKey()).isNotEqualTo(e2.getEncapsulatedKey());
                // Ciphertexts should differ (different nonces)
                assertThat(e1.getCiphertext()).isNotEqualTo(e2.getCiphertext());
            }
        }
    }

    @Nested
    @DisplayName("Size estimation")
    class SizeEstimationTest {

        @Test
        @DisplayName("should estimate encrypted size correctly")
        void shouldEstimateSizeCorrectly() {
            HybridEncryptor encryptor = HybridEncryptor.create();
            int plaintextSize = 100;
            
            try (KemKeyPair keyPair = encryptor.generateKeyPair()) {
                EncryptedMessage encrypted = encryptor.encrypt(
                    keyPair.getEncodedPublicKey(), SecureBytes.randomBytes(plaintextSize));
                
                int estimatedSize = encryptor.estimateEncryptedSize(plaintextSize);
                int actualSize = encrypted.toBytes().length;
                
                // Estimate should be close to actual
                assertThat(estimatedSize).isCloseTo(actualSize, within(10));
            }
        }

        @Test
        @DisplayName("should show significant overhead for PQC")
        void shouldShowPqcOverhead() {
            HybridEncryptor hybridEncryptor = HybridEncryptor.create();
            HybridEncryptor classicalEncryptor = HybridEncryptor.createClassicalOnly();
            
            int hybridOverhead = hybridEncryptor.getEncryptionOverhead();
            int classicalOverhead = classicalEncryptor.getEncryptionOverhead();
            
            System.out.printf("Encryption overhead - Hybrid: %d bytes, Classical: %d bytes%n",
                hybridOverhead, classicalOverhead);
            
            // Hybrid should have significantly more overhead
            assertThat(hybridOverhead).isGreaterThan(classicalOverhead * 10);
        }
    }

    @Nested
    @DisplayName("Algorithm compatibility")
    class AlgorithmCompatibilityTest {

        @Test
        @DisplayName("should reject message from different algorithm")
        void shouldRejectDifferentAlgorithm() {
            HybridEncryptor hybridEncryptor = HybridEncryptor.create();
            HybridEncryptor classicalEncryptor = HybridEncryptor.createClassicalOnly();
            
            byte[] plaintext = "Test".getBytes(StandardCharsets.UTF_8);
            
            try (KemKeyPair classicalKey = classicalEncryptor.generateKeyPair()) {
                EncryptedMessage encrypted = classicalEncryptor.encrypt(
                    classicalKey.getEncodedPublicKey(), plaintext);
                
                // Try to decrypt with hybrid encryptor
                try (KemKeyPair hybridKey = hybridEncryptor.generateKeyPair()) {
                    assertThatThrownBy(() -> hybridEncryptor.decrypt(hybridKey, encrypted))
                        .isInstanceOf(EncryptionException.class)
                        .hasMessageContaining("Algorithm mismatch");
                }
            }
        }
    }

    @Nested
    @DisplayName("Compression (GzipCompressor)")
    class CompressionTest {

        @Test
        @DisplayName("should encrypt and decrypt with GzipCompressor")
        void shouldEncryptAndDecryptWithGzip() {
            HybridEncryptor encryptor = HybridEncryptor.create();
            encryptor.setCompressor(new GzipCompressor());
            byte[] plaintext = "Hello, compressed encryption!".getBytes(StandardCharsets.UTF_8);

            try (KemKeyPair keyPair = encryptor.generateKeyPair()) {
                EncryptedMessage encrypted = encryptor.encrypt(
                    keyPair.getEncodedPublicKey(), plaintext);

                assertThat(encrypted.getCompressionAlgorithm()).isEqualTo(CompressionAlgorithm.GZIP);

                byte[] decrypted = encryptor.decrypt(keyPair, encrypted);
                assertThat(decrypted).isEqualTo(plaintext);
            }
        }

        @Test
        @DisplayName("should fail decrypt without compressor when message was compressed")
        void shouldFailDecryptWithoutCompressorWhenCompressed() {
            HybridEncryptor encryptorWithCompression = HybridEncryptor.create();
            encryptorWithCompression.setCompressor(new GzipCompressor());
            HybridEncryptor encryptorWithoutCompression = HybridEncryptor.create();

            byte[] plaintext = "Secret".getBytes(StandardCharsets.UTF_8);

            try (KemKeyPair keyPair = encryptorWithCompression.generateKeyPair()) {
                EncryptedMessage encrypted = encryptorWithCompression.encrypt(
                    keyPair.getEncodedPublicKey(), plaintext);

                assertThatThrownBy(() -> encryptorWithoutCompression.decrypt(keyPair, encrypted))
                    .isInstanceOf(EncryptionException.class)
                    .hasMessageContaining("Cannot decompress");
            }
        }

        @Test
        @DisplayName("serialize/deserialize with compression preserves and decrypts")
        void serializeDeserializeWithCompression() {
            HybridEncryptor encryptor = HybridEncryptor.create();
            encryptor.setCompressor(new GzipCompressor());
            byte[] plaintext = "Round-trip with compression".getBytes(StandardCharsets.UTF_8);

            try (KemKeyPair keyPair = encryptor.generateKeyPair()) {
                EncryptedMessage encrypted = encryptor.encrypt(
                    keyPair.getEncodedPublicKey(), plaintext);
                byte[] serialized = encrypted.toBytes();
                EncryptedMessage restored = EncryptedMessage.fromBytes(serialized);
                assertThat(restored.getCompressionAlgorithm()).isEqualTo(CompressionAlgorithm.GZIP);
                byte[] decrypted = encryptor.decrypt(keyPair, restored);
                assertThat(decrypted).isEqualTo(plaintext);
            }
        }
    }

    @Nested
    @DisplayName("Compression benchmark (bytes and time)")
    class CompressionBenchmarkTest {

        static Stream<DataCompressor> provideCompressors() {
            return Stream.of(
                    new GzipCompressor(),
                    new FourierCompressor(),
                    new ZstdCompressor(),
                    new Lz4Compressor()
            );
        }

        private static final int WARMUP_ITERATIONS = 3;
        private static final int MEASURED_ITERATIONS = 20;

        @ParameterizedTest(name = "Compression: {0}")
        @MethodSource("provideCompressors")
        @DisplayName("compare encrypted size: with vs without Gzip")
        void compareEncryptedSizeWithAndWithoutGzip(DataCompressor compressor) {
            HybridEncryptor withoutCompression = HybridEncryptor.create();
            HybridEncryptor withCompression = HybridEncryptor.create();
            withCompression.setCompressor(compressor);

            String algoName = compressor.getAlgorithm().name();

            // Well-compressible payload: repetitive text
            String repetitive = "The quick brown fox jumps over the lazy dog. ".repeat(500);
            byte[] plaintext = repetitive.getBytes(StandardCharsets.UTF_8);
            int plaintextBytes = plaintext.length;

            try (KemKeyPair keyPair = withoutCompression.generateKeyPair()) {
                EncryptedMessage encryptedNoComp = withoutCompression.encrypt(
                    keyPair.getEncodedPublicKey(), plaintext);
                EncryptedMessage encryptedWithComp = withCompression.encrypt(
                    keyPair.getEncodedPublicKey(), plaintext);

                int sizeNoComp = encryptedNoComp.toBytes().length;
                int sizeWithComp = encryptedWithComp.toBytes().length;

                System.out.println("--- Размер сообщения | Алгоритм: " + algoName + " ---");
                System.out.printf("Исходный plaintext: %d байт%n", plaintextBytes);
                System.out.printf("Без сжатия:         %d байт%n", sizeNoComp);
                System.out.printf("Со сжатием (%s): %d байт%n", algoName, sizeWithComp);
                System.out.printf("Экономия:           %d байт (%.1f%%)%n%n",
                        sizeNoComp - sizeWithComp,
                        100.0 * (sizeNoComp - sizeWithComp) / sizeNoComp);

                assertThat(sizeWithComp).isLessThanOrEqualTo(sizeNoComp);
            }
        }

        @ParameterizedTest(name = "Compression: {0}")
        @MethodSource("provideCompressors")
        @DisplayName("compare encryption/decryption time: with vs without compression")
        void compareEncryptionDecryptionTimeWithAndWithoutCompression(DataCompressor compressor) {
            HybridEncryptor withoutCompression = HybridEncryptor.create();
            HybridEncryptor withCompression = HybridEncryptor.create();
            withCompression.setCompressor(new GzipCompressor());

            String algoName = compressor.getAlgorithm().name();

            String payload = "Benchmark payload. ".repeat(1000);
            byte[] plaintext = payload.getBytes(StandardCharsets.UTF_8);

            try (KemKeyPair keyPair = withoutCompression.generateKeyPair()) {
                // Warmup
                for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                    withoutCompression.encrypt(keyPair.getEncodedPublicKey(), plaintext);
                    withCompression.encrypt(keyPair.getEncodedPublicKey(), plaintext);
                }

                long t0 = System.nanoTime();
                for (int i = 0; i < MEASURED_ITERATIONS; i++) {
                    EncryptedMessage enc = withoutCompression.encrypt(
                        keyPair.getEncodedPublicKey(), plaintext);
                    withoutCompression.decrypt(keyPair, enc);
                }
                long timeNoCompNs = System.nanoTime() - t0;

                long t1 = System.nanoTime();
                for (int i = 0; i < MEASURED_ITERATIONS; i++) {
                    EncryptedMessage enc = withCompression.encrypt(
                        keyPair.getEncodedPublicKey(), plaintext);
                    withCompression.decrypt(keyPair, enc);
                }
                long timeWithCompNs = System.nanoTime() - t1;

                double msNoComp = timeNoCompNs / 1_000_000.0 / MEASURED_ITERATIONS;
                double msWithComp = timeWithCompNs / 1_000_000.0 / MEASURED_ITERATIONS;

                System.out.println("--- Время (шифрование+дешифрование) | Алгоритм: " + algoName + " ---");
                System.out.printf("Среднее за %d итераций%n", MEASURED_ITERATIONS);
                System.out.printf("Без сжатия:        %.2f мс%n", msNoComp);
                System.out.printf("Со сжатием (%s): %.2f мс%n", algoName, msWithComp);
                System.out.printf("Разница:           %.2f мс (сжатие %.2fx)%n%n",
                        msWithComp - msNoComp, msWithComp / msNoComp);
            }
        }

        @ParameterizedTest(name = "Compression: {0}")
        @MethodSource("provideCompressors")
        @DisplayName("size with random data (compression may increase size)")
        void sizeWithRandomDataCompressionMayIncrease(DataCompressor compressor) {
            HybridEncryptor withoutCompression = HybridEncryptor.create();
            HybridEncryptor withCompression = HybridEncryptor.create();
            withCompression.setCompressor(compressor);

            String algoName = compressor.getAlgorithm().name();
            byte[] randomPlaintext = SecureBytes.randomBytes(5000);

            try (KemKeyPair keyPair = withoutCompression.generateKeyPair()) {
                EncryptedMessage encNoComp = withoutCompression.encrypt(
                        keyPair.getEncodedPublicKey(), randomPlaintext);
                EncryptedMessage encWithComp = withCompression.encrypt(
                        keyPair.getEncodedPublicKey(), randomPlaintext);

                int sizeNoComp = encNoComp.toBytes().length;
                int sizeWithComp = encWithComp.toBytes().length;

                System.out.println("--- Случайные данные (5000 байт) | Алгоритм: " + algoName + " ---");
                System.out.printf("Без сжатия: %d байт%n", sizeNoComp);
                System.out.printf("Со сжатием: %d байт%n%n", sizeWithComp);

                byte[] decrypted = withCompression.decrypt(keyPair, encWithComp);
                assertThat(decrypted).isEqualTo(randomPlaintext);
            }
        }
    }
}
