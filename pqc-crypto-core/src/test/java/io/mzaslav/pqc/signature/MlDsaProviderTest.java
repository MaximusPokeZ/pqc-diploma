package io.mzaslav.pqc.signature;

import io.mzaslav.pqc.algorithm.MlDsaParameterSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link MlDsaProvider}.
 * 
 * These tests verify ML-DSA (FIPS 204) digital signatures
 * using Java 25's native JEP 497 support.
 */
@DisplayName("MlDsaProvider")
class MlDsaProviderTest {

    @Nested
    @DisplayName("Key generation")
    class KeyGenerationTest {

        @ParameterizedTest
        @EnumSource(MlDsaParameterSet.class)
        @DisplayName("should generate key pairs for all parameter sets")
        void shouldGenerateKeyPairs(MlDsaParameterSet parameterSet) {
            MlDsaProvider provider = new MlDsaProvider(parameterSet);
            
            try (SignatureKeyPair keyPair = provider.generateKeyPair()) {
                assertThat(keyPair).isNotNull();
                assertThat(keyPair.getParameterSet()).isEqualTo(parameterSet);
                assertThat(keyPair.getPublicKey()).isNotNull();
                assertThat(keyPair.getPrivateKey()).isNotNull();
            }
        }

        @Test
        @DisplayName("should generate unique key pairs")
        void shouldGenerateUniqueKeyPairs() {
            MlDsaProvider provider = new MlDsaProvider();
            
            try (SignatureKeyPair kp1 = provider.generateKeyPair();
                 SignatureKeyPair kp2 = provider.generateKeyPair()) {
                
                assertThat(kp1.getEncodedPublicKey())
                    .isNotEqualTo(kp2.getEncodedPublicKey());
            }
        }

        @Test
        @DisplayName("should demonstrate PQC signature size overhead")
        void shouldShowSignatureSizeOverhead() {
            System.out.println("=== ML-DSA Sizes (demonstrating PQC overhead) ===");
            for (MlDsaParameterSet ps : MlDsaParameterSet.values()) {
                System.out.printf("%s: Public=%d, Private=%d, Signature=%d%n",
                    ps.getParameterName(),
                    ps.getPublicKeySize(),
                    ps.getPrivateKeySize(),
                    ps.getSignatureSize());
            }
            System.out.println("(Compare to Ed25519: Public=32, Private=64, Signature=64)");
            
            // ML-DSA signatures are much larger than classical
            assertThat(MlDsaParameterSet.ML_DSA_44.getSignatureSize())
                .isGreaterThan(64 * 30); // >30x larger than Ed25519
        }
    }

    @Nested
    @DisplayName("Signing and verification")
    class SigningTest {

        @ParameterizedTest
        @EnumSource(MlDsaParameterSet.class)
        @DisplayName("should sign and verify for all parameter sets")
        void shouldSignAndVerify(MlDsaParameterSet parameterSet) {
            MlDsaProvider provider = new MlDsaProvider(parameterSet);
            byte[] message = "Test message for signing".getBytes(StandardCharsets.UTF_8);
            
            try (SignatureKeyPair keyPair = provider.generateKeyPair()) {
                byte[] signature = provider.sign(keyPair, message);
                
                assertThat(signature).isNotEmpty();
                // Signature size should match parameter set
                assertThat(signature.length).isLessThanOrEqualTo(
                    parameterSet.getSignatureSize() + 100); // Allow some encoding overhead
                
                boolean valid = provider.verify(keyPair.getPublicKey(), message, signature);
                assertThat(valid).isTrue();
            }
        }

        @Test
        @DisplayName("should verify with encoded public key")
        void shouldVerifyWithEncodedKey() {
            MlDsaProvider provider = new MlDsaProvider();
            byte[] message = "Test message".getBytes(StandardCharsets.UTF_8);
            
            try (SignatureKeyPair keyPair = provider.generateKeyPair()) {
                byte[] signature = provider.sign(keyPair, message);
                byte[] encodedPublicKey = keyPair.getEncodedPublicKey();
                
                boolean valid = provider.verify(encodedPublicKey, message, signature);
                assertThat(valid).isTrue();
            }
        }

        @Test
        @DisplayName("should reject modified message")
        void shouldRejectModifiedMessage() {
            MlDsaProvider provider = new MlDsaProvider();
            byte[] originalMessage = "Original message".getBytes(StandardCharsets.UTF_8);
            byte[] modifiedMessage = "Modified message".getBytes(StandardCharsets.UTF_8);
            
            try (SignatureKeyPair keyPair = provider.generateKeyPair()) {
                byte[] signature = provider.sign(keyPair, originalMessage);
                
                boolean valid = provider.verify(keyPair.getPublicKey(), modifiedMessage, signature);
                assertThat(valid).isFalse();
            }
        }

        @Test
        @DisplayName("should reject corrupted signature")
        void shouldRejectCorruptedSignature() {
            MlDsaProvider provider = new MlDsaProvider();
            byte[] message = "Test message".getBytes(StandardCharsets.UTF_8);
            
            try (SignatureKeyPair keyPair = provider.generateKeyPair()) {
                byte[] signature = provider.sign(keyPair, message);
                
                // Corrupt the signature
                signature[signature.length / 2] ^= 0xFF;
                
                boolean valid = provider.verify(keyPair.getPublicKey(), message, signature);
                assertThat(valid).isFalse();
            }
        }

        @Test
        @DisplayName("should reject signature from wrong key")
        void shouldRejectWrongKey() {
            MlDsaProvider provider = new MlDsaProvider();
            byte[] message = "Test message".getBytes(StandardCharsets.UTF_8);
            
            try (SignatureKeyPair kp1 = provider.generateKeyPair();
                 SignatureKeyPair kp2 = provider.generateKeyPair()) {
                
                byte[] signature = provider.sign(kp1, message);
                
                // Verify with wrong public key
                boolean valid = provider.verify(kp2.getPublicKey(), message, signature);
                assertThat(valid).isFalse();
            }
        }

        @Test
        @DisplayName("should handle empty message")
        void shouldHandleEmptyMessage() {
            MlDsaProvider provider = new MlDsaProvider();
            byte[] message = new byte[0];
            
            try (SignatureKeyPair keyPair = provider.generateKeyPair()) {
                byte[] signature = provider.sign(keyPair, message);
                boolean valid = provider.verify(keyPair.getPublicKey(), message, signature);
                assertThat(valid).isTrue();
            }
        }

        @Test
        @DisplayName("should handle large message")
        void shouldHandleLargeMessage() {
            MlDsaProvider provider = new MlDsaProvider();
            byte[] message = new byte[1_000_000]; // 1 MB
            new java.util.Random(42).nextBytes(message);
            
            try (SignatureKeyPair keyPair = provider.generateKeyPair()) {
                byte[] signature = provider.sign(keyPair, message);
                boolean valid = provider.verify(keyPair.getPublicKey(), message, signature);
                assertThat(valid).isTrue();
            }
        }
    }

    @Nested
    @DisplayName("Default configuration")
    class DefaultConfigTest {

        @Test
        @DisplayName("default constructor should use ML-DSA-65")
        void defaultShouldUseMlDsa65() {
            MlDsaProvider provider = new MlDsaProvider();
            assertThat(provider.getParameterSet()).isEqualTo(MlDsaParameterSet.ML_DSA_65);
        }

        @Test
        @DisplayName("should report correct signature size")
        void shouldReportCorrectSize() {
            MlDsaProvider provider = new MlDsaProvider(MlDsaParameterSet.ML_DSA_65);
            assertThat(provider.getSignatureSize())
                .isEqualTo(MlDsaParameterSet.ML_DSA_65.getSignatureSize());
        }
    }
}
