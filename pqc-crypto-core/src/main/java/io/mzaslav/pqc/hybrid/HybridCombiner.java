package io.mzaslav.pqc.hybrid;

import io.mzaslav.pqc.exception.EncryptionException;
import io.mzaslav.pqc.util.SecureBytes;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Hybrid secret combiner for post-quantum cryptographic security.
 * <p>
 * This class provides secure combination of multiple shared secrets from
 * different key encapsulation mechanisms (e.g., X25519 + ML-KEM) into a
 * single unified key material.
 * </p>
 * <p>
 * The combination is performed using HKDF (HMAC-based Key Derivation Function)
 * with SHA-256, ensuring that:
 * <ul>
 *   <li>An attacker must break ALL constituent algorithms to compromise the secret</li>
 *   <li>The output is uniformly distributed regardless of input distributions</li>
 *   <li>Domain separation prevents key reuse attacks</li>
 * </ul>
 * </p>
 * <p>
 * <b>Security Model:</b> The hybrid scheme is secure as long as at least one
 * of the underlying algorithms remains secure. This provides defense-in-depth
 * against both classical and quantum adversaries.
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public final class HybridCombiner {
    
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final int HASH_OUTPUT_SIZE = 32;
    
    /**
     * Default domain separator for hybrid key derivation.
     */
    public static final String DEFAULT_DOMAIN = "PQC-HYBRID-KEM-v1";
    
    private final byte[] domainSeparator;
    
    /**
     * Creates a new hybrid combiner with the default domain separator.
     */
    public HybridCombiner() {
        this(DEFAULT_DOMAIN);
    }
    
    /**
     * Creates a new hybrid combiner with a custom domain separator.
     * <p>
     * The domain separator provides additional context binding and prevents
     * key reuse across different applications or protocols.
     * </p>
     *
     * @param domain the domain separator string
     */
    public HybridCombiner(String domain) {
        Objects.requireNonNull(domain, "Domain cannot be null");
        this.domainSeparator = domain.getBytes(StandardCharsets.UTF_8);
    }
    
    /**
     * Combines two shared secrets into a single derived key.
     * <p>
     * Uses HKDF-Extract followed by HKDF-Expand to combine the secrets.
     * The classical secret is used as the salt, and the PQC secret as
     * the input keying material.
     * </p>
     *
     * @param classicalSecret the shared secret from classical algorithm (e.g., X25519)
     * @param pqcSecret       the shared secret from post-quantum algorithm (e.g., ML-KEM)
     * @param outputLength    the desired output length in bytes
     * @return the combined key material
     * @throws EncryptionException if the combination fails
     */
    public byte[] combine(byte[] classicalSecret, byte[] pqcSecret, int outputLength) {
        Objects.requireNonNull(classicalSecret, "Classical secret cannot be null");
        Objects.requireNonNull(pqcSecret, "PQC secret cannot be null");
        if (outputLength <= 0) {
            throw new IllegalArgumentException("Output length must be positive");
        }
        
        try {
            // Concatenate secrets with length prefixes for unambiguous parsing
            byte[] ikm = createInputKeyingMaterial(classicalSecret, pqcSecret);
            
            // HKDF-Extract: PRK = HMAC(salt, IKM)
            byte[] prk = hkdfExtract(domainSeparator, ikm);
            
            // HKDF-Expand: OKM = HMAC(PRK, info || counter)
            byte[] okm = hkdfExpand(prk, domainSeparator, outputLength);
            
            // Clean up intermediate values
            SecureBytes.wipe(ikm);
            SecureBytes.wipe(prk);
            
            return okm;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new EncryptionException("Failed to combine secrets", e);
        }
    }
    
    /**
     * Combines two shared secrets into a 32-byte key suitable for AES-256.
     *
     * @param classicalSecret the shared secret from classical algorithm
     * @param pqcSecret       the shared secret from post-quantum algorithm
     * @return a 32-byte combined key
     */
    public byte[] combine(byte[] classicalSecret, byte[] pqcSecret) {
        return combine(classicalSecret, pqcSecret, HASH_OUTPUT_SIZE);
    }
    
    /**
     * Combines multiple shared secrets into a single derived key.
     *
     * @param outputLength the desired output length in bytes
     * @param secrets      the secrets to combine (at least 2 required)
     * @return the combined key material
     * @throws IllegalArgumentException if fewer than 2 secrets are provided
     */
    public byte[] combineMultiple(int outputLength, byte[]... secrets) {
        if (secrets == null || secrets.length < 2) {
            throw new IllegalArgumentException("At least 2 secrets are required");
        }
        
        // Combine pairwise
        byte[] combined = combine(secrets[0], secrets[1], HASH_OUTPUT_SIZE);
        
        for (int i = 2; i < secrets.length; i++) {
            byte[] newCombined = combine(combined, secrets[i], HASH_OUTPUT_SIZE);
            SecureBytes.wipe(combined);
            combined = newCombined;
        }
        
        // Final expansion to desired length
        if (outputLength != HASH_OUTPUT_SIZE) {
            try {
                byte[] result = hkdfExpand(combined, domainSeparator, outputLength);
                SecureBytes.wipe(combined);
                return result;
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new EncryptionException("Failed to expand combined secret", e);
            }
        }
        
        return combined;
    }
    
    /**
     * Creates unambiguous input keying material from two secrets.
     */
    private byte[] createInputKeyingMaterial(byte[] secret1, byte[] secret2) {
        // Format: len1 (4 bytes) || secret1 || len2 (4 bytes) || secret2
        byte[] result = new byte[4 + secret1.length + 4 + secret2.length];
        int offset = 0;
        
        // Write length-prefixed secret1
        writeInt(result, offset, secret1.length);
        offset += 4;
        System.arraycopy(secret1, 0, result, offset, secret1.length);
        offset += secret1.length;
        
        // Write length-prefixed secret2
        writeInt(result, offset, secret2.length);
        offset += 4;
        System.arraycopy(secret2, 0, result, offset, secret2.length);
        
        return result;
    }
    
    /**
     * HKDF-Extract: extracts a pseudo-random key from input keying material.
     */
    private byte[] hkdfExtract(byte[] salt, byte[] ikm) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(
            salt.length > 0 ? salt : new byte[HASH_OUTPUT_SIZE], HMAC_ALGORITHM);
        mac.init(keySpec);
        return mac.doFinal(ikm);
    }
    
    /**
     * HKDF-Expand: expands a pseudo-random key to desired length.
     */
    private byte[] hkdfExpand(byte[] prk, byte[] info, int length) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        int hashLen = HASH_OUTPUT_SIZE;
        int n = (length + hashLen - 1) / hashLen;
        
        if (n > 255) {
            throw new IllegalArgumentException("Output length too large");
        }
        
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(prk, HMAC_ALGORITHM);
        
        byte[] okm = new byte[length];
        byte[] t = new byte[0];
        int offset = 0;
        
        for (int i = 1; i <= n; i++) {
            mac.init(keySpec);
            mac.update(t);
            mac.update(info);
            mac.update((byte) i);
            t = mac.doFinal();
            
            int copyLen = Math.min(hashLen, length - offset);
            System.arraycopy(t, 0, okm, offset, copyLen);
            offset += copyLen;
        }
        
        SecureBytes.wipe(t);
        return okm;
    }
    
    /**
     * Writes an integer as 4 big-endian bytes.
     */
    private static void writeInt(byte[] dest, int offset, int value) {
        dest[offset] = (byte) (value >>> 24);
        dest[offset + 1] = (byte) (value >>> 16);
        dest[offset + 2] = (byte) (value >>> 8);
        dest[offset + 3] = (byte) value;
    }
    
    /**
     * Computes a simple SHA-256 hash (for non-security-critical uses).
     *
     * @param data the data to hash
     * @return the SHA-256 hash
     */
    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("SHA-256 not available", e);
        }
    }
}
