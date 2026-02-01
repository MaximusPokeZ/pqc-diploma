package io.mzaslav.pqc.encryption;

import io.mzaslav.pqc.exception.EncryptionException;
import io.mzaslav.pqc.util.SecureBytes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link AeadEncryptor}.
 */
@DisplayName("AeadEncryptor")
class AeadEncryptorTest {

    private AeadEncryptor encryptor;
    private byte[] testKey;

    @BeforeEach
    void setUp() {
        testKey = SecureBytes.randomBytes(32);
        encryptor = new AeadEncryptor(testKey);
    }

    @Nested
    @DisplayName("Constructor")
    class ConstructorTest {

        @Test
        @DisplayName("should accept 32-byte key")
        void shouldAccept32ByteKey() {
            assertThatCode(() -> new AeadEncryptor(SecureBytes.randomBytes(32)))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should reject null key")
        void shouldRejectNullKey() {
            assertThatThrownBy(() -> new AeadEncryptor(null))
                .isInstanceOf(NullPointerException.class);
        }

        @Test
        @DisplayName("should reject wrong key size")
        void shouldRejectWrongKeySize() {
            assertThatThrownBy(() -> new AeadEncryptor(new byte[16]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
        }
    }

    @Nested
    @DisplayName("Encryption")
    class EncryptionTest {

        @Test
        @DisplayName("should encrypt and decrypt plaintext")
        void shouldEncryptAndDecrypt() {
            byte[] plaintext = "Hello, Post-Quantum World!".getBytes(StandardCharsets.UTF_8);
            
            byte[] ciphertext = encryptor.encrypt(plaintext);
            byte[] decrypted = encryptor.decrypt(ciphertext);
            
            assertThat(decrypted).isEqualTo(plaintext);
        }

        @Test
        @DisplayName("should encrypt with associated data")
        void shouldEncryptWithAAD() {
            byte[] plaintext = "Secret message".getBytes(StandardCharsets.UTF_8);
            byte[] aad = "header data".getBytes(StandardCharsets.UTF_8);
            
            byte[] ciphertext = encryptor.encrypt(plaintext, aad);
            byte[] decrypted = encryptor.decrypt(ciphertext, aad);
            
            assertThat(decrypted).isEqualTo(plaintext);
        }

        @Test
        @DisplayName("should fail decryption with wrong AAD")
        void shouldFailWithWrongAAD() {
            byte[] plaintext = "Secret".getBytes(StandardCharsets.UTF_8);
            byte[] aad = "correct".getBytes(StandardCharsets.UTF_8);
            byte[] wrongAad = "wrong".getBytes(StandardCharsets.UTF_8);
            
            byte[] ciphertext = encryptor.encrypt(plaintext, aad);
            
            assertThatThrownBy(() -> encryptor.decrypt(ciphertext, wrongAad))
                .isInstanceOf(EncryptionException.class);
        }

        @Test
        @DisplayName("should produce different ciphertexts for same plaintext")
        void shouldProduceDifferentCiphertexts() {
            byte[] plaintext = "Same message".getBytes(StandardCharsets.UTF_8);
            
            byte[] ct1 = encryptor.encrypt(plaintext);
            byte[] ct2 = encryptor.encrypt(plaintext);
            
            assertThat(ct1).isNotEqualTo(ct2);
        }

        @Test
        @DisplayName("should include nonce in ciphertext")
        void shouldIncludeNonceInCiphertext() {
            byte[] plaintext = "Test".getBytes(StandardCharsets.UTF_8);
            byte[] ciphertext = encryptor.encrypt(plaintext);
            
            // Ciphertext should be: nonce (12) + encrypted + tag (16)
            int expectedSize = AeadEncryptor.calculateCiphertextSize(plaintext.length);
            assertThat(ciphertext).hasSize(expectedSize);
        }

        @Test
        @DisplayName("should handle empty plaintext")
        void shouldHandleEmptyPlaintext() {
            byte[] plaintext = new byte[0];
            
            byte[] ciphertext = encryptor.encrypt(plaintext);
            byte[] decrypted = encryptor.decrypt(ciphertext);
            
            assertThat(decrypted).isEmpty();
        }

        @Test
        @DisplayName("should handle large plaintext")
        void shouldHandleLargePlaintext() {
            byte[] plaintext = SecureBytes.randomBytes(100_000);
            
            byte[] ciphertext = encryptor.encrypt(plaintext);
            byte[] decrypted = encryptor.decrypt(ciphertext);
            
            assertThat(decrypted).isEqualTo(plaintext);
        }
    }

    @Nested
    @DisplayName("Decryption errors")
    class DecryptionErrorTest {

        @Test
        @DisplayName("should fail for corrupted ciphertext")
        void shouldFailForCorruptedCiphertext() {
            byte[] plaintext = "Test".getBytes(StandardCharsets.UTF_8);
            byte[] ciphertext = encryptor.encrypt(plaintext);
            
            // Corrupt a byte
            ciphertext[ciphertext.length - 1] ^= 0xFF;
            
            assertThatThrownBy(() -> encryptor.decrypt(ciphertext))
                .isInstanceOf(EncryptionException.class)
                .hasMessageContaining("authentication");
        }

        @Test
        @DisplayName("should fail for truncated ciphertext")
        void shouldFailForTruncatedCiphertext() {
            byte[] ciphertext = new byte[10]; // Too short
            
            assertThatThrownBy(() -> encryptor.decrypt(ciphertext))
                .isInstanceOf(EncryptionException.class);
        }

        @Test
        @DisplayName("should fail for null ciphertext")
        void shouldFailForNullCiphertext() {
            assertThatThrownBy(() -> encryptor.decrypt(null))
                .isInstanceOf(NullPointerException.class);
        }
    }

    @Nested
    @DisplayName("Size calculations")
    class SizeCalculationTest {

        @Test
        @DisplayName("should calculate ciphertext size correctly")
        void shouldCalculateCiphertextSize() {
            int plaintextSize = 100;
            int expectedSize = AeadEncryptor.NONCE_SIZE + plaintextSize + 16; // 16 = tag size
            
            assertThat(AeadEncryptor.calculateCiphertextSize(plaintextSize))
                .isEqualTo(expectedSize);
        }

        @Test
        @DisplayName("should calculate plaintext size correctly")
        void shouldCalculatePlaintextSize() {
            int plaintextSize = 100;
            int ciphertextSize = AeadEncryptor.calculateCiphertextSize(plaintextSize);
            
            assertThat(AeadEncryptor.calculatePlaintextSize(ciphertextSize))
                .isEqualTo(plaintextSize);
        }
    }
}
