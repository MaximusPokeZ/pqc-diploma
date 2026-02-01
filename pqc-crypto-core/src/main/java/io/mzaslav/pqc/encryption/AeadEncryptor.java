package io.mzaslav.pqc.encryption;

import io.mzaslav.pqc.exception.EncryptionException;
import io.mzaslav.pqc.util.SecureBytes;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * AEAD (Authenticated Encryption with Associated Data) encryptor using AES-GCM.
 * <p>
 * This class provides symmetric encryption with authentication using AES-256-GCM.
 * AES-GCM ensures both confidentiality and integrity of the encrypted data.
 * </p>
 * <p>
 * <b>Nonce Handling:</b> Each encryption operation generates a fresh random nonce
 * (IV). The nonce is prepended to the ciphertext for decryption. Using the same
 * nonce with the same key is CATASTROPHIC for security - this implementation
 * prevents that by always generating random nonces.
 * </p>
 * <p>
 * <b>Output Format:</b>
 * <pre>
 * | Nonce (12 bytes) | Ciphertext + Auth Tag |
 * </pre>
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public final class AeadEncryptor {
    
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";
    
    /**
     * Standard AES-GCM nonce size in bytes.
     */
    public static final int NONCE_SIZE = 12;
    
    /**
     * Standard AES-GCM authentication tag size in bits.
     */
    public static final int TAG_SIZE_BITS = 128;
    
    /**
     * AES-256 key size in bytes.
     */
    public static final int KEY_SIZE = 32;
    
    private final byte[] key;
    
    /**
     * Creates a new AEAD encryptor with the specified key.
     *
     * @param key the 32-byte AES-256 key
     * @throws IllegalArgumentException if the key is not 32 bytes
     */
    public AeadEncryptor(byte[] key) {
        Objects.requireNonNull(key, "Key cannot be null");
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException(
                "Key must be " + KEY_SIZE + " bytes, got " + key.length);
        }
        this.key = SecureBytes.copy(key);
    }
    
    /**
     * Encrypts plaintext with optional associated data.
     * <p>
     * The returned ciphertext includes the nonce at the beginning.
     * </p>
     *
     * @param plaintext      the data to encrypt
     * @param associatedData optional associated data (authenticated but not encrypted)
     * @return the nonce + ciphertext + auth tag
     * @throws EncryptionException if encryption fails
     */
    public byte[] encrypt(byte[] plaintext, byte[] associatedData) {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null");
        
        try {
            // Generate random nonce
            byte[] nonce = SecureBytes.randomBytes(NONCE_SIZE);
            
            // Initialize cipher
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(key, KEY_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE_BITS, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            
            // Add associated data if provided
            if (associatedData != null && associatedData.length > 0) {
                cipher.updateAAD(associatedData);
            }
            
            // Encrypt
            byte[] ciphertextWithTag = cipher.doFinal(plaintext);
            
            // Combine nonce + ciphertext
            return SecureBytes.concat(nonce, ciphertextWithTag);
            
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Encryption failed", e);
        }
    }
    
    /**
     * Encrypts plaintext without associated data.
     *
     * @param plaintext the data to encrypt
     * @return the nonce + ciphertext + auth tag
     * @throws EncryptionException if encryption fails
     */
    public byte[] encrypt(byte[] plaintext) {
        return encrypt(plaintext, null);
    }
    
    /**
     * Decrypts ciphertext with optional associated data.
     *
     * @param ciphertext     the nonce + ciphertext + auth tag
     * @param associatedData optional associated data (must match encryption)
     * @return the decrypted plaintext
     * @throws EncryptionException if decryption fails (including auth tag mismatch)
     */
    public byte[] decrypt(byte[] ciphertext, byte[] associatedData) {
        Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");
        
        if (ciphertext.length < NONCE_SIZE + TAG_SIZE_BITS / 8) {
            throw new EncryptionException("Ciphertext too short");
        }
        
        try {
            // Extract nonce
            byte[] nonce = SecureBytes.slice(ciphertext, 0, NONCE_SIZE);
            byte[] encryptedData = SecureBytes.slice(ciphertext, NONCE_SIZE, 
                ciphertext.length - NONCE_SIZE);
            
            // Initialize cipher
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(key, KEY_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE_BITS, nonce);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            
            // Add associated data if provided
            if (associatedData != null && associatedData.length > 0) {
                cipher.updateAAD(associatedData);
            }
            
            // Decrypt and verify
            return cipher.doFinal(encryptedData);
            
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(
                "Decryption failed - authentication tag mismatch or corrupted data", e);
        }
    }
    
    /**
     * Decrypts ciphertext without associated data.
     *
     * @param ciphertext the nonce + ciphertext + auth tag
     * @return the decrypted plaintext
     * @throws EncryptionException if decryption fails
     */
    public byte[] decrypt(byte[] ciphertext) {
        return decrypt(ciphertext, null);
    }
    
    /**
     * Securely wipes the key from memory.
     * After calling this method, the encryptor cannot be used.
     */
    public void destroy() {
        SecureBytes.wipe(key);
    }
    
    /**
     * Calculates the ciphertext size for a given plaintext size.
     *
     * @param plaintextSize the plaintext size in bytes
     * @return the total ciphertext size (nonce + ciphertext + tag)
     */
    public static int calculateCiphertextSize(int plaintextSize) {
        // Nonce + plaintext + auth tag (16 bytes)
        return NONCE_SIZE + plaintextSize + TAG_SIZE_BITS / 8;
    }
    
    /**
     * Calculates the plaintext size from a ciphertext size.
     *
     * @param ciphertextSize the ciphertext size in bytes
     * @return the plaintext size
     */
    public static int calculatePlaintextSize(int ciphertextSize) {
        return ciphertextSize - NONCE_SIZE - TAG_SIZE_BITS / 8;
    }
}
