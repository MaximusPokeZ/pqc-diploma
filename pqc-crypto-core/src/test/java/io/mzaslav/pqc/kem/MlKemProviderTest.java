package io.mzaslav.pqc.kem;

import io.mzaslav.pqc.algorithm.KemAlgorithm;
import io.mzaslav.pqc.algorithm.MlKemParameterSet;
import io.mzaslav.pqc.util.SecureBytes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link MlKemProvider}.
 * 
 * These tests verify ML-KEM (FIPS 203) key encapsulation mechanism
 * using Java 25's native JEP 496 support.
 */
@DisplayName("MlKemProvider")
class MlKemProviderTest {

    @Nested
    @DisplayName("Key generation")
    class KeyGenerationTest {

        @ParameterizedTest
        @EnumSource(MlKemParameterSet.class)
        @DisplayName("should generate key pairs for all parameter sets")
        void shouldGenerateKeyPairs(MlKemParameterSet parameterSet) {
            MlKemProvider provider = new MlKemProvider(parameterSet);
            
            try (KemKeyPair keyPair = provider.generateKeyPair()) {
                assertThat(keyPair).isNotNull();
                assertThat(keyPair.getAlgorithm()).isEqualTo(KemAlgorithm.ML_KEM);
                assertThat(keyPair.getPublicKey()).isNotNull();
                assertThat(keyPair.getPrivateKey()).isNotNull();
            }
        }

        @Test
        @DisplayName("should generate unique key pairs each time")
        void shouldGenerateUniqueKeyPairs() {
            MlKemProvider provider = new MlKemProvider();
            
            try (KemKeyPair kp1 = provider.generateKeyPair();
                 KemKeyPair kp2 = provider.generateKeyPair()) {
                
                assertThat(kp1.getEncodedPublicKey())
                    .isNotEqualTo(kp2.getEncodedPublicKey());
            }
        }

        @ParameterizedTest
        @EnumSource(MlKemParameterSet.class)
        @DisplayName("should generate keys with expected sizes")
        void shouldGenerateCorrectKeySizes(MlKemParameterSet parameterSet) {
            MlKemProvider provider = new MlKemProvider(parameterSet);
            
            try (KemKeyPair keyPair = provider.generateKeyPair()) {
                // Note: Encoded keys include ASN.1 header, so they're larger
                // than the raw key sizes specified in the parameter set
                assertThat(keyPair.getEncodedPublicKey().length)
                    .isGreaterThanOrEqualTo(parameterSet.getPublicKeySize());
            }
        }
    }

    @Nested
    @DisplayName("Encapsulation and decapsulation")
    class EncapsulationTest {

        @ParameterizedTest
        @EnumSource(MlKemParameterSet.class)
        @DisplayName("should encapsulate and decapsulate for all parameter sets")
        void shouldEncapsulateAndDecapsulate(MlKemParameterSet parameterSet) {
            MlKemProvider provider = new MlKemProvider(parameterSet);
            
            try (KemKeyPair keyPair = provider.generateKeyPair()) {
                // Encapsulate
                EncapsulationResult result = provider.encapsulate(keyPair.getPublicKey());
                assertThat(result.getCiphertext()).isNotEmpty();
                assertThat(result.getSharedSecret()).hasSize(parameterSet.getSharedSecretSize());
                
                // Decapsulate
                byte[] decapsulatedSecret = provider.decapsulate(keyPair, result.getCiphertext());
                
                // Secrets should match
                assertThat(SecureBytes.constantTimeEquals(
                    result.getSharedSecret(), decapsulatedSecret)).isTrue();
                
                result.destroy();
            }
        }

        @Test
        @DisplayName("should work with encoded public key")
        void shouldWorkWithEncodedPublicKey() {
            MlKemProvider provider = new MlKemProvider();
            
            try (KemKeyPair keyPair = provider.generateKeyPair()) {
                byte[] encodedPublicKey = keyPair.getEncodedPublicKey();
                
                // Encapsulate using encoded key
                EncapsulationResult result = provider.encapsulate(encodedPublicKey);
                
                // Decapsulate
                byte[] decapsulatedSecret = provider.decapsulate(keyPair, result.getCiphertext());
                
                assertThat(SecureBytes.constantTimeEquals(
                    result.getSharedSecret(), decapsulatedSecret)).isTrue();
                
                result.destroy();
            }
        }

        @Test
        @DisplayName("should produce different shared secrets for different encapsulations")
        void shouldProduceDifferentSecrets() {
            MlKemProvider provider = new MlKemProvider();
            
            try (KemKeyPair keyPair = provider.generateKeyPair();
                 EncapsulationResult r1 = provider.encapsulate(keyPair.getPublicKey());
                 EncapsulationResult r2 = provider.encapsulate(keyPair.getPublicKey())) {
                
                assertThat(r1.getSharedSecret()).isNotEqualTo(r2.getSharedSecret());
                assertThat(r1.getCiphertext()).isNotEqualTo(r2.getCiphertext());
            }
        }
    }

    @Nested
    @DisplayName("Size verification")
    class SizeVerificationTest {

        @ParameterizedTest
        @EnumSource(MlKemParameterSet.class)
        @DisplayName("should report correct ciphertext and secret sizes")
        void shouldReportCorrectSizes(MlKemParameterSet parameterSet) {
            MlKemProvider provider = new MlKemProvider(parameterSet);
            
            assertThat(provider.getCiphertextSize())
                .isEqualTo(parameterSet.getCiphertextSize());
            assertThat(provider.getSharedSecretSize())
                .isEqualTo(parameterSet.getSharedSecretSize());
        }

        @Test
        @DisplayName("should demonstrate PQC key size overhead")
        void shouldShowKeySizeOverhead() {
            // This test documents the significant size increase of PQC keys
            MlKemProvider ml512 = new MlKemProvider(MlKemParameterSet.ML_KEM_512);
            MlKemProvider ml768 = new MlKemProvider(MlKemParameterSet.ML_KEM_768);
            MlKemProvider ml1024 = new MlKemProvider(MlKemParameterSet.ML_KEM_1024);
            
            System.out.println("=== ML-KEM Key Sizes (demonstrating PQC overhead) ===");
            System.out.printf("ML-KEM-512:  Public=%d, Private=%d, Ciphertext=%d%n",
                MlKemParameterSet.ML_KEM_512.getPublicKeySize(),
                MlKemParameterSet.ML_KEM_512.getPrivateKeySize(),
                MlKemParameterSet.ML_KEM_512.getCiphertextSize());
            System.out.printf("ML-KEM-768:  Public=%d, Private=%d, Ciphertext=%d%n",
                MlKemParameterSet.ML_KEM_768.getPublicKeySize(),
                MlKemParameterSet.ML_KEM_768.getPrivateKeySize(),
                MlKemParameterSet.ML_KEM_768.getCiphertextSize());
            System.out.printf("ML-KEM-1024: Public=%d, Private=%d, Ciphertext=%d%n",
                MlKemParameterSet.ML_KEM_1024.getPublicKeySize(),
                MlKemParameterSet.ML_KEM_1024.getPrivateKeySize(),
                MlKemParameterSet.ML_KEM_1024.getCiphertextSize());
            System.out.println("(Compare to X25519: Public=32, Private=32, Ciphertext=32)");
            
            // All PQC keys are much larger than classical keys
            assertThat(MlKemParameterSet.ML_KEM_512.getPublicKeySize())
                .isGreaterThan(32 * 20); // >20x larger than X25519
        }
    }

    @Nested
    @DisplayName("Default parameter set")
    class DefaultParameterSetTest {

        @Test
        @DisplayName("default constructor should use ML-KEM-768")
        void defaultShouldUseMlKem768() {
            MlKemProvider provider = new MlKemProvider();
            assertThat(provider.getParameterSet()).isEqualTo(MlKemParameterSet.ML_KEM_768);
        }
    }
}
