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
 * Tests for {@link HybridKemProvider}.
 * 
 * These tests verify the hybrid X25519 + ML-KEM key encapsulation mechanism.
 */
@DisplayName("HybridKemProvider")
class HybridKemProviderTest {

    @Nested
    @DisplayName("Key generation")
    class KeyGenerationTest {

        @ParameterizedTest
        @EnumSource(MlKemParameterSet.class)
        @DisplayName("should generate hybrid key pairs for all ML-KEM parameter sets")
        void shouldGenerateHybridKeyPairs(MlKemParameterSet parameterSet) {
            HybridKemProvider provider = new HybridKemProvider(parameterSet);
            
            try (KemKeyPair keyPair = provider.generateKeyPair()) {
                assertThat(keyPair).isNotNull();
                assertThat(keyPair.getAlgorithm()).isEqualTo(KemAlgorithm.HYBRID);
                
                // Verify it's a composite key
                assertThat(keyPair.getPublicKey())
                    .isInstanceOf(HybridKemProvider.CompositePublicKey.class);
                assertThat(keyPair.getPrivateKey())
                    .isInstanceOf(HybridKemProvider.CompositePrivateKey.class);
            }
        }

        @Test
        @DisplayName("hybrid keys should be larger than either component")
        void hybridKeysShouldBeLarger() {
            HybridKemProvider hybridProvider = new HybridKemProvider();
            X25519Provider x25519Provider = new X25519Provider();
            MlKemProvider mlKemProvider = new MlKemProvider();
            
            try (KemKeyPair hybridKp = hybridProvider.generateKeyPair();
                 KemKeyPair x25519Kp = x25519Provider.generateKeyPair();
                 KemKeyPair mlKemKp = mlKemProvider.generateKeyPair()) {
                
                int hybridSize = hybridKp.getEncodedPublicKey().length;
                int x25519Size = x25519Kp.getEncodedPublicKey().length;
                int mlKemSize = mlKemKp.getEncodedPublicKey().length;
                
                // Hybrid key contains both + length prefixes
                assertThat(hybridSize).isGreaterThan(x25519Size + mlKemSize);
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
            HybridKemProvider provider = new HybridKemProvider(parameterSet);
            
            try (KemKeyPair keyPair = provider.generateKeyPair()) {
                // Encapsulate using CompositePublicKey
                EncapsulationResult result = provider.encapsulate(keyPair.getPublicKey());
                
                assertThat(result.getAlgorithm()).isEqualTo(KemAlgorithm.HYBRID);
                assertThat(result.getCiphertext()).isNotEmpty();
                assertThat(result.getSharedSecret()).hasSize(32);
                
                // Decapsulate
                byte[] decapsulated = provider.decapsulate(keyPair, result.getCiphertext());
                
                assertThat(SecureBytes.constantTimeEquals(
                    result.getSharedSecret(), decapsulated)).isTrue();
                
                result.destroy();
            }
        }

        @Test
        @DisplayName("should encapsulate using encoded public key")
        void shouldEncapsulateWithEncodedKey() {
            HybridKemProvider provider = new HybridKemProvider();
            
            try (KemKeyPair keyPair = provider.generateKeyPair()) {
                byte[] encodedPublicKey = keyPair.getEncodedPublicKey();
                
                // Encapsulate using encoded key bytes
                EncapsulationResult result = provider.encapsulate(encodedPublicKey);
                
                // Decapsulate
                byte[] decapsulated = provider.decapsulate(keyPair, result.getCiphertext());
                
                assertThat(SecureBytes.constantTimeEquals(
                    result.getSharedSecret(), decapsulated)).isTrue();
                
                result.destroy();
            }
        }

        @Test
        @DisplayName("hybrid ciphertext should contain both X25519 and ML-KEM ciphertexts")
        void ciphertextShouldContainBoth() {
            HybridKemProvider hybridProvider = new HybridKemProvider();
            X25519Provider x25519Provider = new X25519Provider();
            MlKemProvider mlKemProvider = new MlKemProvider();
            
            try (KemKeyPair keyPair = hybridProvider.generateKeyPair();
                 EncapsulationResult result = hybridProvider.encapsulate(keyPair.getPublicKey())) {
                
                int hybridCtSize = result.getCiphertextSize();
                int x25519CtSize = x25519Provider.getCiphertextSize();
                int mlKemCtSize = mlKemProvider.getCiphertextSize();
                
                // Hybrid ciphertext = length prefix (4) + X25519 CT + length prefix (4) + ML-KEM CT
                int expectedSize = 4 + x25519CtSize + 4 + mlKemCtSize;
                assertThat(hybridCtSize).isEqualTo(expectedSize);
            }
        }
    }

    @Nested
    @DisplayName("Security properties")
    class SecurityPropertiesTest {

        @Test
        @DisplayName("each encapsulation should produce unique shared secret")
        void shouldProduceUniqueSecrets() {
            HybridKemProvider provider = new HybridKemProvider();
            
            try (KemKeyPair keyPair = provider.generateKeyPair();
                 EncapsulationResult r1 = provider.encapsulate(keyPair.getPublicKey());
                 EncapsulationResult r2 = provider.encapsulate(keyPair.getPublicKey())) {
                
                assertThat(r1.getSharedSecret()).isNotEqualTo(r2.getSharedSecret());
            }
        }

        @Test
        @DisplayName("different key pairs should produce different secrets for same ciphertext concept")
        void differentKeysShouldProduceDifferentSecrets() {
            HybridKemProvider provider = new HybridKemProvider();
            
            try (KemKeyPair kp1 = provider.generateKeyPair();
                 KemKeyPair kp2 = provider.generateKeyPair();
                 EncapsulationResult r1 = provider.encapsulate(kp1.getPublicKey());
                 EncapsulationResult r2 = provider.encapsulate(kp2.getPublicKey())) {
                
                // Even if we could somehow use same randomness (we can't), 
                // different keys = different secrets
                assertThat(r1.getSharedSecret()).isNotEqualTo(r2.getSharedSecret());
            }
        }
    }

    @Nested
    @DisplayName("Size reporting")
    class SizeReportingTest {

        @Test
        @DisplayName("should report correct ciphertext and secret sizes")
        void shouldReportCorrectSizes() {
            HybridKemProvider provider = new HybridKemProvider(MlKemParameterSet.ML_KEM_768);
            
            // 4 + X25519 (44) + 4 + ML-KEM-768 (1088)
            assertThat(provider.getCiphertextSize()).isEqualTo(4 + 44 + 4 + 1088);
            assertThat(provider.getSharedSecretSize()).isEqualTo(32);
        }
    }

    @Nested
    @DisplayName("Default configuration")
    class DefaultConfigTest {

        @Test
        @DisplayName("default constructor should use ML-KEM-768")
        void defaultShouldUseMlKem768() {
            HybridKemProvider provider = new HybridKemProvider();
            assertThat(provider.getMlKemParameterSet()).isEqualTo(MlKemParameterSet.ML_KEM_768);
        }
    }
}
