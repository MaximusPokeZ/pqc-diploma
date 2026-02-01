package io.mzaslav.pqc.hybrid;

import io.mzaslav.pqc.algorithm.MlDsaParameterSet;
import io.mzaslav.pqc.signature.SignatureKeyPair;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link HybridSigner}.
 * 
 * These tests verify the high-level ML-DSA digital signature API.
 */
@DisplayName("HybridSigner")
class HybridSignerTest {

    @Nested
    @DisplayName("Factory methods")
    class FactoryMethodsTest {

        @Test
        @DisplayName("create() should use ML-DSA-65")
        void createShouldUseMlDsa65() {
            HybridSigner signer = HybridSigner.create();
            assertThat(signer.getParameterSet()).isEqualTo(MlDsaParameterSet.ML_DSA_65);
        }

        @ParameterizedTest
        @EnumSource(MlDsaParameterSet.class)
        @DisplayName("should support all ML-DSA parameter sets")
        void shouldSupportAllParameterSets(MlDsaParameterSet parameterSet) {
            HybridSigner signer = HybridSigner.create(parameterSet);
            assertThat(signer.getParameterSet()).isEqualTo(parameterSet);
        }
    }

    @Nested
    @DisplayName("Signing and verification")
    class SigningTest {

        @Test
        @DisplayName("should sign and verify message")
        void shouldSignAndVerify() {
            HybridSigner signer = HybridSigner.create();
            byte[] message = "Important document to sign".getBytes(StandardCharsets.UTF_8);
            
            try (SignatureKeyPair keyPair = signer.generateKeyPair()) {
                byte[] signature = signer.sign(keyPair, message);
                
                assertThat(signature).isNotEmpty();
                
                boolean valid = signer.verify(keyPair, message, signature);
                assertThat(valid).isTrue();
            }
        }

        @Test
        @DisplayName("should verify with encoded public key")
        void shouldVerifyWithEncodedKey() {
            HybridSigner signer = HybridSigner.create();
            byte[] message = "Test message".getBytes(StandardCharsets.UTF_8);
            
            try (SignatureKeyPair keyPair = signer.generateKeyPair()) {
                byte[] signature = signer.sign(keyPair, message);
                byte[] encodedPublicKey = keyPair.getEncodedPublicKey();
                
                boolean valid = signer.verify(encodedPublicKey, message, signature);
                assertThat(valid).isTrue();
            }
        }

        @ParameterizedTest
        @EnumSource(MlDsaParameterSet.class)
        @DisplayName("should work with all parameter sets")
        void shouldWorkWithAllParameterSets(MlDsaParameterSet parameterSet) {
            HybridSigner signer = HybridSigner.create(parameterSet);
            byte[] message = "Test".getBytes(StandardCharsets.UTF_8);
            
            try (SignatureKeyPair keyPair = signer.generateKeyPair()) {
                byte[] signature = signer.sign(keyPair, message);
                boolean valid = signer.verify(keyPair, message, signature);
                assertThat(valid).isTrue();
            }
        }
    }

    @Nested
    @DisplayName("Verification failures")
    class VerificationFailuresTest {

        @Test
        @DisplayName("should reject modified message")
        void shouldRejectModifiedMessage() {
            HybridSigner signer = HybridSigner.create();
            byte[] original = "Original".getBytes(StandardCharsets.UTF_8);
            byte[] modified = "Modified".getBytes(StandardCharsets.UTF_8);
            
            try (SignatureKeyPair keyPair = signer.generateKeyPair()) {
                byte[] signature = signer.sign(keyPair, original);
                
                boolean valid = signer.verify(keyPair, modified, signature);
                assertThat(valid).isFalse();
            }
        }

        @Test
        @DisplayName("should reject corrupted signature")
        void shouldRejectCorruptedSignature() {
            HybridSigner signer = HybridSigner.create();
            byte[] message = "Test".getBytes(StandardCharsets.UTF_8);
            
            try (SignatureKeyPair keyPair = signer.generateKeyPair()) {
                byte[] signature = signer.sign(keyPair, message);
                
                // Corrupt signature
                signature[100] ^= 0xFF;
                
                boolean valid = signer.verify(keyPair, message, signature);
                assertThat(valid).isFalse();
            }
        }

        @Test
        @DisplayName("should reject wrong key")
        void shouldRejectWrongKey() {
            HybridSigner signer = HybridSigner.create();
            byte[] message = "Test".getBytes(StandardCharsets.UTF_8);
            
            try (SignatureKeyPair correctKey = signer.generateKeyPair();
                 SignatureKeyPair wrongKey = signer.generateKeyPair()) {
                
                byte[] signature = signer.sign(correctKey, message);
                
                boolean valid = signer.verify(wrongKey, message, signature);
                assertThat(valid).isFalse();
            }
        }
    }

    @Nested
    @DisplayName("Size information")
    class SizeInfoTest {

        @Test
        @DisplayName("should report correct sizes")
        void shouldReportCorrectSizes() {
            HybridSigner signer = HybridSigner.create(MlDsaParameterSet.ML_DSA_65);
            
            assertThat(signer.getSignatureSize())
                .isEqualTo(MlDsaParameterSet.ML_DSA_65.getSignatureSize());
            assertThat(signer.getPublicKeySize())
                .isEqualTo(MlDsaParameterSet.ML_DSA_65.getPublicKeySize());
            assertThat(signer.getPrivateKeySize())
                .isEqualTo(MlDsaParameterSet.ML_DSA_65.getPrivateKeySize());
        }

        @Test
        @DisplayName("should demonstrate large signature sizes")
        void shouldDemonstrateLargeSignatures() {
            System.out.println("=== ML-DSA Signature Sizes ===");
            for (MlDsaParameterSet ps : MlDsaParameterSet.values()) {
                HybridSigner signer = HybridSigner.create(ps);
                System.out.printf("%s: Signature=%d bytes%n",
                    ps.getParameterName(), signer.getSignatureSize());
            }
            
            // All PQC signatures are much larger than classical
            HybridSigner signer = HybridSigner.create(MlDsaParameterSet.ML_DSA_44);
            assertThat(signer.getSignatureSize()).isGreaterThan(2000);
        }
    }
}
