package io.mzaslav.pqc.hybrid;

import io.mzaslav.pqc.algorithm.KemAlgorithm;
import io.mzaslav.pqc.algorithm.MlKemParameterSet;
import io.mzaslav.pqc.algorithm.ClassicalKemAlgorithm;
import io.mzaslav.pqc.compression.DataCompressor;
import io.mzaslav.pqc.compression.CompressionAlgorithm;
import io.mzaslav.pqc.encryption.AeadEncryptor;
import io.mzaslav.pqc.exception.EncryptionException;
import io.mzaslav.pqc.kem.*;
import io.mzaslav.pqc.util.SecureBytes;

import java.util.Objects;

/**
 * High-level facade for hybrid post-quantum data encryption.
 * <p>
 * Combines a classical KEM (X25519 or SECP256R1) with a post-quantum KEM
 * (ML-KEM, FIPS 203) to derive a shared secret, then encrypts the payload
 * with AES-256-GCM (AEAD). Optional payload compression (GZIP, ZSTD, LZ4,
 * FOURIER) can be configured via {@link #setCompressor(DataCompressor)}.
 * <p>
 * The hybrid construction is secure as long as <i>at least one</i> of the
 * underlying KEMs remains unbroken, which protects ciphertexts against the
 * "Harvest Now, Decrypt Later" threat model.
 * <p>
 * Three operating modes are supported via factory methods:
 * <ul>
 *   <li>{@link #create()} / {@link #create(MlKemParameterSet)} - hybrid mode (recommended)</li>
 *   <li>{@link #createPqcOnly(MlKemParameterSet)} - post-quantum only</li>
 *   <li>{@link #createClassicalOnly()} - classical only (legacy interop)</li>
 * </ul>
 * <p>
 * Example:
 * <pre>{@code
 * HybridEncryptor encryptor = HybridEncryptor.create();
 * try (KemKeyPair kp = encryptor.generateKeyPair()) {
 *     EncryptedMessage msg = encryptor.encrypt(kp.getEncodedPublicKey(), payload);
 *     byte[] plaintext = encryptor.decrypt(kp, msg);
 * }
 * }</pre>
 *
 * @author mzaslav
 * @since 1.0
 */
public final class HybridEncryptor {

    private final KemProvider kemProvider;
    private final MlKemParameterSet mlKemParameterSet;
    private DataCompressor compressor;

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

    private static KemProvider createClassicalProvider(ClassicalKemAlgorithm algorithm) {
        if (algorithm == ClassicalKemAlgorithm.SECP256R1) {
            return new Secp256r1Provider();
        }
        // Default to the very fast X25519 curve.
        return new X25519Provider();
    }


    /**
     * Creates a hybrid encryptor with recommended defaults (X25519 + ML-KEM-768).
     *
     * @return a configured hybrid encryptor
     */
    public static HybridEncryptor create() {
        return create(ClassicalKemAlgorithm.X25519, MlKemParameterSet.ML_KEM_768);
    }

    /**
     * Creates a hybrid encryptor with X25519 and the chosen ML-KEM parameter set.
     *
     * @param mlKemParameterSet the ML-KEM parameter set to combine with X25519
     * @return a configured hybrid encryptor
     */
    public static HybridEncryptor create(MlKemParameterSet mlKemParameterSet) {
        return create(ClassicalKemAlgorithm.X25519, mlKemParameterSet);
    }

    /**
     * Creates a hybrid encryptor with manually selected classical and PQC algorithms.
     *
     * @param classicalAlgo     the classical KEM algorithm (X25519 or SECP256R1)
     * @param mlKemParameterSet the ML-KEM parameter set
     * @return a configured hybrid encryptor
     */
    public static HybridEncryptor create(ClassicalKemAlgorithm classicalAlgo, MlKemParameterSet mlKemParameterSet) {
        Objects.requireNonNull(classicalAlgo, "Classical algorithm cannot be null");
        Objects.requireNonNull(mlKemParameterSet, "Parameter set cannot be null");

        KemProvider classicalProvider = createClassicalProvider(classicalAlgo);
        HybridKemProvider kemProvider = new HybridKemProvider(classicalProvider, mlKemParameterSet);

        return new HybridEncryptor(kemProvider, mlKemParameterSet);
    }

    /**
     * Creates a PQC-only encryptor that uses ML-KEM with no classical fallback.
     * <p>
     * Use this for evaluation/benchmarking; for production prefer
     * {@link #create(ClassicalKemAlgorithm, MlKemParameterSet)}.
     *
     * @param mlKemParameterSet the ML-KEM parameter set
     * @return a PQC-only encryptor
     */
    public static HybridEncryptor createPqcOnly(MlKemParameterSet mlKemParameterSet) {
        Objects.requireNonNull(mlKemParameterSet, "Parameter set cannot be null");
        MlKemProvider kemProvider = new MlKemProvider(mlKemParameterSet);
        return new HybridEncryptor(kemProvider, mlKemParameterSet);
    }

    /**
     * Creates a classical-only encryptor (X25519 by default).
     * <p>
     * Provided for legacy interoperability; offers no quantum resistance.
     *
     * @return a classical-only encryptor using X25519
     */
    public static HybridEncryptor createClassicalOnly() {
        return createClassicalOnly(ClassicalKemAlgorithm.X25519);
    }

    /**
     * Creates a classical-only encryptor with the specified curve.
     *
     * @param classicalAlgo the classical KEM algorithm
     * @return a classical-only encryptor
     */
    public static HybridEncryptor createClassicalOnly(ClassicalKemAlgorithm classicalAlgo) {
        Objects.requireNonNull(classicalAlgo, "Classical algorithm cannot be null");
        KemProvider kemProvider = createClassicalProvider(classicalAlgo);
        return new HybridEncryptor(kemProvider, null);
    }

    /**
     * @return the KEM algorithm used by this encryptor
     */
    public KemAlgorithm getAlgorithm() {
        return kemProvider.getAlgorithm();
    }

    /**
     * @return the ML-KEM parameter set, or {@code null} for classical-only mode
     */
    public MlKemParameterSet getMlKemParameterSet() {
        return mlKemParameterSet;
    }

    /**
     * Generates a new recipient key pair appropriate for the configured mode.
     * <p>
     * In hybrid mode, the returned key pair carries both classical and PQC
     * key material concatenated with length prefixes.
     *
     * @return a fresh KEM key pair
     */
    public KemKeyPair generateKeyPair() {
        return kemProvider.generateKeyPair();
    }

    /**
     * Encrypts a payload to the given recipient public key.
     *
     * @param recipientPublicKey encoded public key bytes
     * @param plaintext          payload to encrypt
     * @return an {@link EncryptedMessage} that can be serialised via {@link EncryptedMessage#toBytes()}
     */
    public EncryptedMessage encrypt(byte[] recipientPublicKey, byte[] plaintext) {
        return encrypt(recipientPublicKey, plaintext, null);
    }

    /**
     * Encrypts a payload with optional associated data (AAD) authenticated by AEAD.
     *
     * @param recipientPublicKey encoded public key bytes
     * @param plaintext          payload to encrypt
     * @param associatedData     additional authenticated data (may be {@code null})
     * @return an {@link EncryptedMessage}
     */
    public EncryptedMessage encrypt(byte[] recipientPublicKey, byte[] plaintext, byte[] associatedData) {
        Objects.requireNonNull(recipientPublicKey, "Recipient public key cannot be null");
        Objects.requireNonNull(plaintext, "Plaintext cannot be null");

        byte[] dataToEncrypt = plaintext;
        CompressionAlgorithm compAlgo = CompressionAlgorithm.NONE;

        if (this.compressor != null) {
            byte[] compressedData = this.compressor.compress(plaintext);
            if (compressedData != null && compressedData.length < plaintext.length) {
                dataToEncrypt = compressedData;
                compAlgo = this.compressor.getAlgorithm();
            }
        }

        EncapsulationResult kemResult = null;
        byte[] sharedSecret = null;

        try {
            kemResult = kemProvider.encapsulate(recipientPublicKey);
            sharedSecret = kemResult.getSharedSecret();

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
                    ciphertext
            );

        } finally {
            if (kemResult != null) kemResult.destroy();
            SecureBytes.wipe(sharedSecret);
        }
    }

    /**
     * Decrypts an {@link EncryptedMessage} using the recipient's key pair.
     *
     * @param keyPair          the recipient's KEM key pair
     * @param encryptedMessage the message to decrypt
     * @return the recovered plaintext
     */
    public byte[] decrypt(KemKeyPair keyPair, EncryptedMessage encryptedMessage) {
        return decrypt(keyPair, encryptedMessage, null);
    }

    /**
     * Decrypts an {@link EncryptedMessage} with associated data verification.
     *
     * @param keyPair          the recipient's KEM key pair
     * @param encryptedMessage the message to decrypt
     * @param associatedData   AAD that was authenticated during encryption (may be {@code null})
     * @return the recovered plaintext
     * @throws EncryptionException if the algorithm or AAD does not match,
     *                             or if AEAD authentication fails
     */
    public byte[] decrypt(KemKeyPair keyPair, EncryptedMessage encryptedMessage, byte[] associatedData) {
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        Objects.requireNonNull(encryptedMessage, "Encrypted message cannot be null");

        if (encryptedMessage.getAlgorithm() != kemProvider.getAlgorithm()) {
            throw new EncryptionException(String.format(
                    "Algorithm mismatch: message uses %s, encryptor uses %s",
                    encryptedMessage.getAlgorithm(), kemProvider.getAlgorithm()));
        }

        byte[] sharedSecret = null;
        try {
            sharedSecret = kemProvider.decapsulate(keyPair, encryptedMessage.getEncapsulatedKey());

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
     * Convenience overload that decrypts a serialised {@link EncryptedMessage}.
     *
     * @param keyPair        the recipient's KEM key pair
     * @param encryptedBytes the byte form produced by {@link EncryptedMessage#toBytes()}
     * @return the recovered plaintext
     */
    public byte[] decrypt(KemKeyPair keyPair, byte[] encryptedBytes) {
        Objects.requireNonNull(encryptedBytes, "Encrypted bytes cannot be null");
        EncryptedMessage message = EncryptedMessage.fromBytes(encryptedBytes);
        return decrypt(keyPair, message);
    }

    /**
     * Estimates the encrypted message size for the given plaintext size.
     *
     * @param plaintextSize the plaintext size in bytes
     * @return the predicted encrypted message size in bytes
     */
    public int estimateEncryptedSize(int plaintextSize) {
        // Header: version(1) + KemAlgorithm(1) + CompressionAlgo(1) + KEM length(4)
        int headerSize = 1 + 1 + 1 + 4;
        int kemCiphertextSize = kemProvider.getCiphertextSize();
        int aeadOverhead = AeadEncryptor.NONCE_SIZE + 16; // nonce + 16-byte GCM auth tag

        return headerSize + kemCiphertextSize + aeadOverhead + plaintextSize;
    }

    public int getEncryptionOverhead() {
        return estimateEncryptedSize(0);
    }

    @Override
    public String toString() {
        if (mlKemParameterSet != null) {
            return String.format("HybridEncryptor[%s, %s, Compression: %s]",
                    kemProvider.getAlgorithm(), mlKemParameterSet.getParameterName(),
                    compressor != null ? compressor.getAlgorithm() : "NONE");
        }
        return String.format("HybridEncryptor[%s, Compression: %s]",
                kemProvider.getAlgorithm(),
                compressor != null ? compressor.getAlgorithm() : "NONE");
    }
}
