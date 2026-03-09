package io.mzaslav.pqc.hybrid;

import io.mzaslav.pqc.algorithm.KemAlgorithm;
import io.mzaslav.pqc.algorithm.MlKemParameterSet;
import io.mzaslav.pqc.compression.CompressionAlgorithm;
import io.mzaslav.pqc.compression.DataCompressor;
import io.mzaslav.pqc.encryption.AeadEncryptor;
import io.mzaslav.pqc.exception.EncryptionException;
import io.mzaslav.pqc.kem.*;
import io.mzaslav.pqc.util.SecureBytes;

import java.util.Objects;

/**
 * High-level hybrid post-quantum encryption facade.
 * <p>
 * This class provides a simple, secure API for encrypting and decrypting data
 * using hybrid post-quantum cryptography. It combines:
 * <ul>
 *   <li><b>X25519</b> - Classical elliptic curve key exchange</li>
 *   <li><b>ML-KEM</b> - Post-quantum lattice-based KEM (FIPS 203)</li>
 *   <li><b>AES-256-GCM</b> - Authenticated symmetric encryption</li>
 * </ul>
 * </p>
 * <p>
 * <b>Security Model:</b>
 * <ul>
 *   <li>Protects against "Harvest Now, Decrypt Later" attacks</li>
 *   <li>Security is maintained if either X25519 OR ML-KEM remains secure</li>
 *   <li>An attacker must break BOTH algorithms to compromise confidentiality</li>
 *   <li>Forward secrecy via ephemeral KEM encapsulation</li>
 * </ul>
 * </p>
 * <p>
 * Example usage:
 * <pre>{@code
 * // Create encryptor
 * HybridEncryptor encryptor = HybridEncryptor.create();
 * 
 * // Generate recipient's key pair
 * KemKeyPair recipientKeyPair = encryptor.generateKeyPair();
 * 
 * // Encrypt a message to recipient
 * byte[] message = "Secret message".getBytes();
 * EncryptedMessage encrypted = encryptor.encrypt(
 *     recipientKeyPair.getEncodedPublicKey(), message);
 * 
 * // Recipient decrypts
 * byte[] decrypted = encryptor.decrypt(recipientKeyPair, encrypted);
 * }</pre>
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public final class HybridEncryptor {
    
    private final KemProvider kemProvider;
    private final MlKemParameterSet mlKemParameterSet;

    private DataCompressor compressor;

    /**
     * Creates a new hybrid encryptor with the specified KEM provider.
     *
     * @param kemProvider     the KEM provider to use
     * @param mlKemParameterSet the ML-KEM parameter set
     */
    private HybridEncryptor(KemProvider kemProvider, MlKemParameterSet mlKemParameterSet) {
        this.kemProvider = kemProvider;
        this.mlKemParameterSet = mlKemParameterSet;
    }

    /**
     * Sets the data compressor to use.
     *
     * @param compressor the data compressor
     */
    public void setCompressor(DataCompressor compressor) {
        this.compressor = compressor;
    }
    
    /**
     * Creates a hybrid encryptor using X25519 + ML-KEM-768 (recommended).
     *
     * @return a new hybrid encryptor
     */
    public static HybridEncryptor create() {
        return create(MlKemParameterSet.ML_KEM_768);
    }
    
    /**
     * Creates a hybrid encryptor with the specified ML-KEM parameter set.
     *
     * @param mlKemParameterSet the ML-KEM parameter set
     * @return a new hybrid encryptor
     */
    public static HybridEncryptor create(MlKemParameterSet mlKemParameterSet) {
        Objects.requireNonNull(mlKemParameterSet, "Parameter set cannot be null");
        HybridKemProvider kemProvider = new HybridKemProvider(mlKemParameterSet);
        return new HybridEncryptor(kemProvider, mlKemParameterSet);
    }
    
    /**
     * Creates a hybrid encryptor using only ML-KEM (no X25519).
     *
     * @param mlKemParameterSet the ML-KEM parameter set
     * @return a new encryptor using pure ML-KEM
     */
    public static HybridEncryptor createPqcOnly(MlKemParameterSet mlKemParameterSet) {
        Objects.requireNonNull(mlKemParameterSet, "Parameter set cannot be null");
        MlKemProvider kemProvider = new MlKemProvider(mlKemParameterSet);
        return new HybridEncryptor(kemProvider, mlKemParameterSet);
    }
    
    /**
     * Creates a hybrid encryptor using only X25519 (classical, no PQC).
     *
     * @return a new encryptor using pure X25519
     */
    public static HybridEncryptor createClassicalOnly() {
        X25519Provider kemProvider = new X25519Provider();
        return new HybridEncryptor(kemProvider, null);
    }
    
    /**
     * Returns the KEM algorithm being used.
     *
     * @return the KEM algorithm
     */
    public KemAlgorithm getAlgorithm() {
        return kemProvider.getAlgorithm();
    }
    
    /**
     * Returns the ML-KEM parameter set, or null if using classical-only mode.
     *
     * @return the parameter set or null
     */
    public MlKemParameterSet getMlKemParameterSet() {
        return mlKemParameterSet;
    }
    
    /**
     * Generates a new key pair for this encryptor.
     *
     * @return a new KEM key pair
     */
    public KemKeyPair generateKeyPair() {
        return kemProvider.generateKeyPair();
    }
    
    /**
     * Encrypts a message to the recipient's public key.
     * <p>
     * The returned encrypted message contains all information needed
     * for decryption (algorithm, encapsulated key, ciphertext).
     * </p>
     *
     * @param recipientPublicKey the encoded recipient's public key
     * @param plaintext          the message to encrypt
     * @return the encrypted message
     * @throws EncryptionException if encryption fails
     */
    public EncryptedMessage encrypt(byte[] recipientPublicKey, byte[] plaintext) {
        return encrypt(recipientPublicKey, plaintext, null);
    }
    
    /**
     * Encrypts a message with associated data to the recipient's public key.
     * <p>
     * Associated data is authenticated but not encrypted. It must be provided
     * during decryption to verify message integrity.
     * </p>
     *
     * @param recipientPublicKey the encoded recipient's public key
     * @param plaintext          the message to encrypt
     * @param associatedData     optional associated data (for AEAD)
     * @return the encrypted message
     * @throws EncryptionException if encryption fails
     */
    public EncryptedMessage encrypt(byte[] recipientPublicKey, byte[] plaintext, 
                                     byte[] associatedData) {
        Objects.requireNonNull(recipientPublicKey, "Recipient public key cannot be null");
        Objects.requireNonNull(plaintext, "Plaintext cannot be null");

        byte[] dataToEncrypt = plaintext;
        CompressionAlgorithm compAlgo = CompressionAlgorithm.NONE;

        if (this.compressor != null) {
            byte[] compressedData = this.compressor.compress(plaintext);

            if (compressedData.length < plaintext.length) {
                dataToEncrypt = compressedData;
                compAlgo = this.compressor.getAlgorithm();
            }
        }

        EncapsulationResult kemResult = null;
        byte[] sharedSecret = null;
        
        try {
            // Encapsulate to recipient's public key
            kemResult = kemProvider.encapsulate(recipientPublicKey);
            sharedSecret = kemResult.getSharedSecret();
            
            // Encrypt plaintext with derived key
            AeadEncryptor aeadEncryptor = new AeadEncryptor(sharedSecret);
            byte[] ciphertext;
            try {
                ciphertext = aeadEncryptor.encrypt(dataToEncrypt, associatedData);
            } finally {
                aeadEncryptor.destroy();
            }
            
            return new EncryptedMessage(
                kemProvider.getAlgorithm(),
                    compAlgo,
                    kemResult.getCiphertext(),
                    ciphertext);
            
        } finally {
            if (kemResult != null) kemResult.destroy();
            SecureBytes.wipe(sharedSecret);
        }
    }
    
    /**
     * Decrypts an encrypted message using the recipient's key pair.
     *
     * @param keyPair          the recipient's key pair
     * @param encryptedMessage the encrypted message
     * @return the decrypted plaintext
     * @throws EncryptionException if decryption fails
     */
    public byte[] decrypt(KemKeyPair keyPair, EncryptedMessage encryptedMessage) {
        return decrypt(keyPair, encryptedMessage, null);
    }
    
    /**
     * Decrypts an encrypted message with associated data.
     *
     * @param keyPair          the recipient's key pair
     * @param encryptedMessage the encrypted message
     * @param associatedData   optional associated data (must match encryption)
     * @return the decrypted plaintext
     * @throws EncryptionException if decryption fails
     */
    public byte[] decrypt(KemKeyPair keyPair, EncryptedMessage encryptedMessage,
                          byte[] associatedData) {
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        Objects.requireNonNull(encryptedMessage, "Encrypted message cannot be null");
        
        // Verify algorithm matches
        if (encryptedMessage.getAlgorithm() != kemProvider.getAlgorithm()) {
            throw new EncryptionException(String.format(
                "Algorithm mismatch: message uses %s, encryptor uses %s",
                encryptedMessage.getAlgorithm(), kemProvider.getAlgorithm()));
        }
        
        byte[] sharedSecret = null;
        
        try {
            // Decapsulate to get shared secret
            sharedSecret = kemProvider.decapsulate(keyPair, encryptedMessage.getEncapsulatedKey());
            
            // Decrypt ciphertext
            AeadEncryptor aeadEncryptor = new AeadEncryptor(sharedSecret);
            byte[] decryptedData;
            try {
                decryptedData = aeadEncryptor.decrypt(encryptedMessage.getCiphertext(), associatedData);
            } finally {
                aeadEncryptor.destroy();
            }

            CompressionAlgorithm messageCompAlgo = encryptedMessage.getCompressionAlgorithm();
            if (messageCompAlgo != CompressionAlgorithm.NONE) {
                if (this.compressor == null || this.compressor.getAlgorithm() != messageCompAlgo) {
                    throw new EncryptionException(String.format(
                            "Cannot decompress: message requires %s, but provided %s",
                            messageCompAlgo.name(),
                            this.compressor == null ? "NONE" : this.compressor.getAlgorithm().name()
                    ));
                }
                return this.compressor.decompress(decryptedData);
            }
            return decryptedData;

        } finally {
            SecureBytes.wipe(sharedSecret);
        }
    }
    
    /**
     * Decrypts raw encrypted bytes.
     *
     * @param keyPair        the recipient's key pair
     * @param encryptedBytes the serialized encrypted message
     * @return the decrypted plaintext
     * @throws EncryptionException if decryption fails
     */
    public byte[] decrypt(KemKeyPair keyPair, byte[] encryptedBytes) {
        Objects.requireNonNull(encryptedBytes, "Encrypted bytes cannot be null");
        EncryptedMessage message = EncryptedMessage.fromBytes(encryptedBytes);
        return decrypt(keyPair, message);
    }
    
    /**
     * Calculates the approximate encrypted message size for a given plaintext size.
     * <p>
     * This is useful for pre-allocating buffers or estimating storage requirements.
     * Actual sizes may vary slightly.
     * </p>
     *
     * @param plaintextSize the plaintext size in bytes
     * @return the approximate encrypted message size
     */
    public int estimateEncryptedSize(int plaintextSize) {
        // Header (version + algorithm + kem length) + KEM ciphertext + AEAD overhead
        int headerSize = 1 + 1 + 4;
        int kemCiphertextSize = kemProvider.getCiphertextSize();
        int aeadOverhead = AeadEncryptor.NONCE_SIZE + 16; // nonce + auth tag
        
        return headerSize + kemCiphertextSize + aeadOverhead + plaintextSize;
    }
    
    /**
     * Returns the size overhead compared to plaintext.
     * <p>
     * This shows how much larger the encrypted message is compared to the
     * original plaintext due to cryptographic overhead (KEM ciphertext, nonce, auth tag).
     * </p>
     *
     * @return the overhead in bytes
     */
    public int getEncryptionOverhead() {
        return estimateEncryptedSize(0);
    }
    
    @Override
    public String toString() {
        if (mlKemParameterSet != null) {
            return String.format("HybridEncryptor[%s, %s]", 
                kemProvider.getAlgorithm(), mlKemParameterSet.getParameterName());
        }
        return String.format("HybridEncryptor[%s]", kemProvider.getAlgorithm());
    }
}
