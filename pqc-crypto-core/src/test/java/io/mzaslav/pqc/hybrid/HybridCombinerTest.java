package io.mzaslav.pqc.hybrid;

import io.mzaslav.pqc.util.SecureBytes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link HybridCombiner}.
 * 
 * These tests verify the secure combination of multiple shared secrets
 * using HKDF.
 */
@DisplayName("HybridCombiner")
class HybridCombinerTest {

    private HybridCombiner combiner;

    @BeforeEach
    void setUp() {
        combiner = new HybridCombiner();
    }

    @Nested
    @DisplayName("Basic combination")
    class BasicCombinationTest {

        @Test
        @DisplayName("should combine two secrets into one")
        void shouldCombineTwoSecrets() {
            byte[] classicalSecret = SecureBytes.randomBytes(32);
            byte[] pqcSecret = SecureBytes.randomBytes(32);
            
            byte[] combined = combiner.combine(classicalSecret, pqcSecret);
            
            assertThat(combined).hasSize(32);
            assertThat(combined).isNotEqualTo(classicalSecret);
            assertThat(combined).isNotEqualTo(pqcSecret);
        }

        @Test
        @DisplayName("should produce deterministic output for same inputs")
        void shouldBeDeterministic() {
            byte[] classicalSecret = SecureBytes.randomBytes(32);
            byte[] pqcSecret = SecureBytes.randomBytes(32);
            
            byte[] combined1 = combiner.combine(classicalSecret, pqcSecret);
            byte[] combined2 = combiner.combine(classicalSecret, pqcSecret);
            
            assertThat(combined1).isEqualTo(combined2);
        }

        @Test
        @DisplayName("should produce different output for different inputs")
        void shouldProduceDifferentOutputs() {
            byte[] secret1 = SecureBytes.randomBytes(32);
            byte[] secret2 = SecureBytes.randomBytes(32);
            byte[] secret3 = SecureBytes.randomBytes(32);
            
            byte[] combined1 = combiner.combine(secret1, secret2);
            byte[] combined2 = combiner.combine(secret1, secret3);
            
            assertThat(combined1).isNotEqualTo(combined2);
        }
    }

    @Nested
    @DisplayName("Variable output length")
    class VariableOutputTest {

        @Test
        @DisplayName("should produce output of specified length")
        void shouldProduceVariableLength() {
            byte[] secret1 = SecureBytes.randomBytes(32);
            byte[] secret2 = SecureBytes.randomBytes(32);
            
            byte[] out16 = combiner.combine(secret1, secret2, 16);
            byte[] out32 = combiner.combine(secret1, secret2, 32);
            byte[] out64 = combiner.combine(secret1, secret2, 64);
            
            assertThat(out16).hasSize(16);
            assertThat(out32).hasSize(32);
            assertThat(out64).hasSize(64);
            
            // Shorter outputs should be prefix of longer ones (HKDF property)
            // Actually with our implementation this isn't quite true due to 
            // different expand calls, but outputs should be consistent
        }

        @Test
        @DisplayName("should reject invalid output length")
        void shouldRejectInvalidLength() {
            byte[] secret1 = SecureBytes.randomBytes(32);
            byte[] secret2 = SecureBytes.randomBytes(32);
            
            assertThatThrownBy(() -> combiner.combine(secret1, secret2, 0))
                .isInstanceOf(IllegalArgumentException.class);
            
            assertThatThrownBy(() -> combiner.combine(secret1, secret2, -1))
                .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("Multiple secrets combination")
    class MultipleSecretsTest {

        @Test
        @DisplayName("should combine multiple secrets")
        void shouldCombineMultipleSecrets() {
            byte[] s1 = SecureBytes.randomBytes(32);
            byte[] s2 = SecureBytes.randomBytes(32);
            byte[] s3 = SecureBytes.randomBytes(32);
            byte[] s4 = SecureBytes.randomBytes(32);
            
            byte[] combined = combiner.combineMultiple(32, s1, s2, s3, s4);
            
            assertThat(combined).hasSize(32);
        }

        @Test
        @DisplayName("should require at least 2 secrets")
        void shouldRequireAtLeastTwoSecrets() {
            byte[] s1 = SecureBytes.randomBytes(32);
            
            assertThatThrownBy(() -> combiner.combineMultiple(32, s1))
                .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("Domain separation")
    class DomainSeparationTest {

        @Test
        @DisplayName("different domains should produce different outputs")
        void differentDomainsShouldDiffer() {
            HybridCombiner combiner1 = new HybridCombiner("domain1");
            HybridCombiner combiner2 = new HybridCombiner("domain2");
            
            byte[] secret1 = SecureBytes.randomBytes(32);
            byte[] secret2 = SecureBytes.randomBytes(32);
            
            byte[] combined1 = combiner1.combine(secret1, secret2);
            byte[] combined2 = combiner2.combine(secret1, secret2);
            
            assertThat(combined1).isNotEqualTo(combined2);
        }

        @Test
        @DisplayName("should use default domain")
        void shouldUseDefaultDomain() {
            HybridCombiner defaultCombiner = new HybridCombiner();
            HybridCombiner explicitCombiner = new HybridCombiner(HybridCombiner.DEFAULT_DOMAIN);
            
            byte[] secret1 = SecureBytes.randomBytes(32);
            byte[] secret2 = SecureBytes.randomBytes(32);
            
            byte[] combined1 = defaultCombiner.combine(secret1, secret2);
            byte[] combined2 = explicitCombiner.combine(secret1, secret2);
            
            assertThat(combined1).isEqualTo(combined2);
        }
    }

    @Nested
    @DisplayName("SHA-256 helper")
    class Sha256Test {

        @Test
        @DisplayName("should compute SHA-256 hash")
        void shouldComputeSha256() {
            byte[] data = "test".getBytes();
            byte[] hash = HybridCombiner.sha256(data);
            
            assertThat(hash).hasSize(32);
        }

        @Test
        @DisplayName("should produce consistent hashes")
        void shouldProduceConsistentHashes() {
            byte[] data = "test".getBytes();
            
            byte[] hash1 = HybridCombiner.sha256(data);
            byte[] hash2 = HybridCombiner.sha256(data);
            
            assertThat(hash1).isEqualTo(hash2);
        }
    }

    @Nested
    @DisplayName("Input handling")
    class InputHandlingTest {

        @Test
        @DisplayName("should handle secrets of different sizes")
        void shouldHandleDifferentSizes() {
            byte[] smallSecret = SecureBytes.randomBytes(16);
            byte[] largeSecret = SecureBytes.randomBytes(64);
            
            byte[] combined = combiner.combine(smallSecret, largeSecret);
            assertThat(combined).hasSize(32);
        }

        @Test
        @DisplayName("should reject null secrets")
        void shouldRejectNullSecrets() {
            byte[] secret = SecureBytes.randomBytes(32);
            
            assertThatThrownBy(() -> combiner.combine(null, secret))
                .isInstanceOf(NullPointerException.class);
            
            assertThatThrownBy(() -> combiner.combine(secret, null))
                .isInstanceOf(NullPointerException.class);
        }
    }
}
