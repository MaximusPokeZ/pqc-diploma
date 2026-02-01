package io.mzaslav.pqc.hybrid;

import io.mzaslav.pqc.algorithm.KemAlgorithm;
import io.mzaslav.pqc.util.SecureBytes;

import java.util.Objects;

/**
 * Represents an encrypted message with its encapsulated key material.
 * <p>
 * This class contains all the information needed for a recipient to
 * decrypt a message:
 * <ul>
 *   <li><b>Algorithm</b> - The KEM algorithm used</li>
 *   <li><b>Encapsulated Key</b> - The KEM ciphertext</li>
 *   <li><b>Ciphertext</b> - The AEAD-encrypted message</li>
 * </ul>
 * </p>
 * <p>
 * <b>Wire Format:</b>
 * <pre>
 * | Version (1 byte) | Algorithm (1 byte) | KEM CT Len (4 bytes) | KEM CT | AEAD CT |
 * </pre>
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public final class EncryptedMessage {
    
    /**
     * Current wire format version.
     */
    public static final byte VERSION = 0x01;
    
    private final KemAlgorithm algorithm;
    private final byte[] encapsulatedKey;
    private final byte[] ciphertext;
    
    /**
     * Creates a new encrypted message.
     *
     * @param algorithm       the KEM algorithm used
     * @param encapsulatedKey the KEM ciphertext (encapsulated key)
     * @param ciphertext      the AEAD-encrypted message
     */
    public EncryptedMessage(KemAlgorithm algorithm, byte[] encapsulatedKey, byte[] ciphertext) {
        this.algorithm = Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        this.encapsulatedKey = Objects.requireNonNull(
            SecureBytes.copy(encapsulatedKey), "Encapsulated key cannot be null");
        this.ciphertext = Objects.requireNonNull(
            SecureBytes.copy(ciphertext), "Ciphertext cannot be null");
    }
    
    /**
     * Returns the KEM algorithm used.
     *
     * @return the algorithm
     */
    public KemAlgorithm getAlgorithm() {
        return algorithm;
    }
    
    /**
     * Returns a copy of the encapsulated key (KEM ciphertext).
     *
     * @return the encapsulated key
     */
    public byte[] getEncapsulatedKey() {
        return SecureBytes.copy(encapsulatedKey);
    }
    
    /**
     * Returns a copy of the AEAD ciphertext.
     *
     * @return the ciphertext
     */
    public byte[] getCiphertext() {
        return SecureBytes.copy(ciphertext);
    }
    
    /**
     * Returns the total size of this encrypted message in bytes.
     *
     * @return the total size
     */
    public int getTotalSize() {
        return 1 + 1 + 4 + encapsulatedKey.length + ciphertext.length;
    }
    
    /**
     * Serializes this encrypted message to bytes.
     *
     * @return the serialized message
     */
    public byte[] toBytes() {
        byte[] result = new byte[getTotalSize()];
        int offset = 0;
        
        // Version
        result[offset++] = VERSION;
        
        // Algorithm
        result[offset++] = (byte) algorithm.ordinal();
        
        // Encapsulated key length (4 bytes, big-endian)
        int kemLen = encapsulatedKey.length;
        result[offset++] = (byte) (kemLen >>> 24);
        result[offset++] = (byte) (kemLen >>> 16);
        result[offset++] = (byte) (kemLen >>> 8);
        result[offset++] = (byte) kemLen;
        
        // Encapsulated key
        System.arraycopy(encapsulatedKey, 0, result, offset, encapsulatedKey.length);
        offset += encapsulatedKey.length;
        
        // Ciphertext
        System.arraycopy(ciphertext, 0, result, offset, ciphertext.length);
        
        return result;
    }
    
    /**
     * Deserializes an encrypted message from bytes.
     *
     * @param data the serialized message
     * @return the deserialized encrypted message
     * @throws IllegalArgumentException if the data is invalid
     */
    public static EncryptedMessage fromBytes(byte[] data) {
        Objects.requireNonNull(data, "Data cannot be null");
        
        if (data.length < 6) {
            throw new IllegalArgumentException("Data too short for encrypted message");
        }
        
        int offset = 0;
        
        // Version
        byte version = data[offset++];
        if (version != VERSION) {
            throw new IllegalArgumentException("Unsupported message version: " + version);
        }
        
        // Algorithm
        int algorithmOrdinal = data[offset++] & 0xFF;
        KemAlgorithm[] algorithms = KemAlgorithm.values();
        if (algorithmOrdinal >= algorithms.length) {
            throw new IllegalArgumentException("Unknown algorithm: " + algorithmOrdinal);
        }
        KemAlgorithm algorithm = algorithms[algorithmOrdinal];
        
        // Encapsulated key length
        int kemLen = ((data[offset] & 0xFF) << 24) |
                     ((data[offset + 1] & 0xFF) << 16) |
                     ((data[offset + 2] & 0xFF) << 8) |
                     (data[offset + 3] & 0xFF);
        offset += 4;
        
        if (offset + kemLen > data.length) {
            throw new IllegalArgumentException("Invalid encapsulated key length");
        }
        
        // Encapsulated key
        byte[] encapsulatedKey = SecureBytes.slice(data, offset, kemLen);
        offset += kemLen;
        
        // Ciphertext (remaining bytes)
        if (offset >= data.length) {
            throw new IllegalArgumentException("Missing ciphertext");
        }
        byte[] ciphertext = SecureBytes.slice(data, offset, data.length - offset);
        
        return new EncryptedMessage(algorithm, encapsulatedKey, ciphertext);
    }
    
    @Override
    public String toString() {
        return String.format("EncryptedMessage[algorithm=%s, kemSize=%d, ctSize=%d]",
            algorithm, encapsulatedKey.length, ciphertext.length);
    }
}
