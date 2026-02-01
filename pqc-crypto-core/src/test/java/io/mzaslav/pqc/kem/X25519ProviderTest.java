package io.mzaslav.pqc.kem;

import io.mzaslav.pqc.algorithm.KemAlgorithm;
import io.mzaslav.pqc.util.SecureBytes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link X25519Provider}.
 * 
 * These tests verify X25519 ECDH key agreement wrapped as a KEM interface.
 */
@DisplayName("X25519Provider")
class X25519ProviderTest {

    private X25519Provider provider;

    @BeforeEach
    void setUp() {
        provider = new X25519Provider();
    }

    @Nested
    @DisplayName("Key generation")
    class KeyGenerationTest {

        @Test
        @DisplayName("should generate valid key pair")
        void shouldGenerateKeyPair() {
            try (KemKeyPair keyPair = provider.generateKeyPair()) {
                assertThat(keyPair).isNotNull();
                assertThat(keyPair.getAlgorithm()).isEqualTo(KemAlgorithm.X25519);
                assertThat(keyPair.getPublicKey()).isNotNull();
                assertThat(keyPair.getPrivateKey()).isNotNull();
            }
        }

        @Test
        @DisplayName("should generate unique key pairs")
        void shouldGenerateUniqueKeyPairs() {
            try (KemKeyPair kp1 = provider.generateKeyPair();
                 KemKeyPair kp2 = provider.generateKeyPair()) {
                
                assertThat(kp1.getEncodedPublicKey())
                    .isNotEqualTo(kp2.getEncodedPublicKey());
            }
        }

        @Test
        @DisplayName("should generate compact keys (compared to PQC)")
        void shouldGenerateCompactKeys() {
            try (KemKeyPair keyPair = provider.generateKeyPair()) {
                // X25519 keys are much smaller than ML-KEM
                assertThat(keyPair.getEncodedPublicKey().length)
                    .isLessThan(100); // ~44 bytes with X.509 encoding
            }
        }
    }

    @Nested
    @DisplayName("Encapsulation and decapsulation")
    class EncapsulationTest {

        @Test
        @DisplayName("should encapsulate and decapsulate successfully")
        void shouldEncapsulateAndDecapsulate() {
            try (KemKeyPair keyPair = provider.generateKeyPair();
                 EncapsulationResult result = provider.encapsulate(keyPair.getPublicKey())) {
                
                assertThat(result.getCiphertext()).isNotEmpty();
                assertThat(result.getSharedSecret()).hasSize(32);
                
                byte[] decapsulatedSecret = provider.decapsulate(keyPair, result.getCiphertext());
                
                assertThat(SecureBytes.constantTimeEquals(
                    result.getSharedSecret(), decapsulatedSecret)).isTrue();
            }
        }

        @Test
        @DisplayName("should work with encoded public key")
        void shouldWorkWithEncodedKey() {
            try (KemKeyPair keyPair = provider.generateKeyPair()) {
                byte[] encodedKey = keyPair.getEncodedPublicKey();
                
                try (EncapsulationResult result = provider.encapsulate(encodedKey)) {
                    byte[] decapsulated = provider.decapsulate(keyPair, result.getCiphertext());
                    
                    assertThat(SecureBytes.constantTimeEquals(
                        result.getSharedSecret(), decapsulated)).isTrue();
                }
            }
        }

        @Test
        @DisplayName("should produce 32-byte shared secrets")
        void shouldProduce32ByteSecrets() {
            try (KemKeyPair keyPair = provider.generateKeyPair();
                 EncapsulationResult result = provider.encapsulate(keyPair.getPublicKey())) {
                
                assertThat(result.getSharedSecretSize()).isEqualTo(32);
                assertThat(provider.getSharedSecretSize()).isEqualTo(32);
            }
        }
    }

    @Nested
    @DisplayName("Size reporting")
    class SizeReportingTest {

        @Test
        @DisplayName("should report correct sizes")
        void shouldReportCorrectSizes() {
            assertThat(provider.getSharedSecretSize()).isEqualTo(32);
            assertThat(provider.getCiphertextSize()).isEqualTo(44); // X.509 encoded
        }
    }
}
