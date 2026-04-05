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
        // По умолчанию всегда используем сверхбыстрый X25519
        return new X25519Provider();
    }


    /**
     * Создает гибридный шифратор с рекомендуемыми дефолтами (X25519 + ML-KEM-768).
     */
    public static HybridEncryptor create() {
        return create(ClassicalKemAlgorithm.X25519, MlKemParameterSet.ML_KEM_768);
    }

    /**
     * Создает гибридный шифратор (X25519 + выбранный ML-KEM).
     */
    public static HybridEncryptor create(MlKemParameterSet mlKemParameterSet) {
        return create(ClassicalKemAlgorithm.X25519, mlKemParameterSet);
    }

    /**
     * Создает гибридный шифратор с ручным выбором обоих алгоритмов (Классика + PQC).
     */
    public static HybridEncryptor create(ClassicalKemAlgorithm classicalAlgo, MlKemParameterSet mlKemParameterSet) {
        Objects.requireNonNull(classicalAlgo, "Classical algorithm cannot be null");
        Objects.requireNonNull(mlKemParameterSet, "Parameter set cannot be null");

        KemProvider classicalProvider = createClassicalProvider(classicalAlgo);
        HybridKemProvider kemProvider = new HybridKemProvider(classicalProvider, mlKemParameterSet);

        return new HybridEncryptor(kemProvider, mlKemParameterSet);
    }

    public static HybridEncryptor createPqcOnly(MlKemParameterSet mlKemParameterSet) {
        Objects.requireNonNull(mlKemParameterSet, "Parameter set cannot be null");
        MlKemProvider kemProvider = new MlKemProvider(mlKemParameterSet);
        return new HybridEncryptor(kemProvider, mlKemParameterSet);
    }

    /**
     * Создает классический шифратор (по умолчанию X25519).
     */
    public static HybridEncryptor createClassicalOnly() {
        return createClassicalOnly(ClassicalKemAlgorithm.X25519);
    }

    /**
     * Создает классический шифратор с выбранной кривой.
     */
    public static HybridEncryptor createClassicalOnly(ClassicalKemAlgorithm classicalAlgo) {
        Objects.requireNonNull(classicalAlgo, "Classical algorithm cannot be null");
        KemProvider kemProvider = createClassicalProvider(classicalAlgo);
        return new HybridEncryptor(kemProvider, null);
    }

    public KemAlgorithm getAlgorithm() {
        return kemProvider.getAlgorithm();
    }

    public MlKemParameterSet getMlKemParameterSet() {
        return mlKemParameterSet;
    }

    public KemKeyPair generateKeyPair() {
        return kemProvider.generateKeyPair();
    }

    public EncryptedMessage encrypt(byte[] recipientPublicKey, byte[] plaintext) {
        return encrypt(recipientPublicKey, plaintext, null);
    }

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

    public byte[] decrypt(KemKeyPair keyPair, EncryptedMessage encryptedMessage) {
        return decrypt(keyPair, encryptedMessage, null);
    }

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

    public byte[] decrypt(KemKeyPair keyPair, byte[] encryptedBytes) {
        Objects.requireNonNull(encryptedBytes, "Encrypted bytes cannot be null");
        EncryptedMessage message = EncryptedMessage.fromBytes(encryptedBytes);
        return decrypt(keyPair, message);
    }

    public int estimateEncryptedSize(int plaintextSize) {
        // Заголовок: версия(1) + KemAlgorithm(1) + CompressionAlgo(1) + размер KEM(4)
        int headerSize = 1 + 1 + 1 + 4;
        int kemCiphertextSize = kemProvider.getCiphertextSize();
        int aeadOverhead = AeadEncryptor.NONCE_SIZE + 16; // nonce + auth tag 16 байт

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
