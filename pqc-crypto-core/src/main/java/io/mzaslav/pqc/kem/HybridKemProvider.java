package io.mzaslav.pqc.kem;

import io.mzaslav.pqc.algorithm.KemAlgorithm;
import io.mzaslav.pqc.algorithm.MlKemParameterSet;
import io.mzaslav.pqc.exception.EncapsulationException;
import io.mzaslav.pqc.exception.KeyGenerationException;
import io.mzaslav.pqc.hybrid.HybridCombiner;
import io.mzaslav.pqc.util.SecureBytes;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Hybrid KEM provider combining X25519 and ML-KEM.
 * <p>
 * This provider implements a hybrid key encapsulation mechanism that combines:
 * <ul>
 *   <li><b>X25519</b> - Classical elliptic curve Diffie-Hellman</li>
 *   <li><b>ML-KEM</b> - Post-quantum lattice-based KEM</li>
 * </ul>
 * </p>
 * <p>
 * The hybrid approach provides defense-in-depth:
 * <ul>
 *   <li>If ML-KEM is broken (but X25519 is not): security is maintained</li>
 *   <li>If X25519 is broken by quantum computers: ML-KEM provides protection</li>
 *   <li>An attacker must break BOTH algorithms to compromise the shared secret</li>
 * </ul>
 * </p>
 * <p>
 * <b>Key Format:</b> Hybrid keys are concatenated as X25519 || ML-KEM with
 * length prefixes for unambiguous parsing.
 * </p>
 * <p>
 * <b>Ciphertext Format:</b> The encapsulated ciphertext contains both
 * X25519 ephemeral public key and ML-KEM ciphertext, concatenated with
 * length prefixes.
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public final class HybridKemProvider implements KemProvider {
    
    private static final int SHARED_SECRET_SIZE = 32;

    private final KemProvider classicalProvider;
    private final MlKemProvider mlKemProvider;
    private final HybridCombiner combiner;
    private final MlKemParameterSet mlKemParameterSet;
    
    /**
     * Creates a new hybrid KEM provider with the specified ML-KEM parameter set.
     *
     * @param mlKemParameterSet the ML-KEM parameter set
     * @throws KeyGenerationException if algorithms are not available
     */
    public HybridKemProvider(KemProvider classicalProvider, MlKemParameterSet mlKemParameterSet) {
        this.classicalProvider = Objects.requireNonNull(classicalProvider, "Classical Provider cannot be null");
        this.mlKemParameterSet = Objects.requireNonNull(mlKemParameterSet, "ML-KEM parameter set cannot be null");
        this.mlKemProvider = new MlKemProvider(mlKemParameterSet);
        this.combiner = new HybridCombiner();
    }

    public HybridKemProvider(MlKemParameterSet mlKemParameterSet) {
        this(new X25519Provider(), mlKemParameterSet);
    }
    
    /**
     * Creates a new hybrid KEM provider with the default ML-KEM parameter set (ML-KEM-768).
     *
     * @throws KeyGenerationException if algorithms are not available
     */
    public HybridKemProvider() {
        this(MlKemParameterSet.getDefault());
    }
    
    /**
     * Returns the ML-KEM parameter set used.
     *
     * @return the parameter set
     */
    public MlKemParameterSet getMlKemParameterSet() {
        return mlKemParameterSet;
    }
    
    @Override
    public KemAlgorithm getAlgorithm() {
        return KemAlgorithm.HYBRID;
    }
    
    @Override
    public KemKeyPair generateKeyPair() {
        // Generate both key pairs
        KemKeyPair x25519KeyPair = classicalProvider.generateKeyPair();
        KemKeyPair mlKemKeyPair = mlKemProvider.generateKeyPair();
        
        try {
            // Combine encoded keys with length prefixes
            byte[] x25519Public = x25519KeyPair.getEncodedPublicKey();
            byte[] mlKemPublic = mlKemKeyPair.getEncodedPublicKey();
            byte[] x25519Private = x25519KeyPair.getEncodedPrivateKey();
            byte[] mlKemPrivate = mlKemKeyPair.getEncodedPrivateKey();
            
            byte[] combinedPublic = encodeHybridKey(x25519Public, mlKemPublic);
            byte[] combinedPrivate = encodeHybridKey(x25519Private, mlKemPrivate);
            
            // Create composite key wrappers
            CompositePublicKey publicKey = new CompositePublicKey(
                x25519KeyPair.getPublicKey(), mlKemKeyPair.getPublicKey());
            CompositePrivateKey privateKey = new CompositePrivateKey(
                x25519KeyPair.getPrivateKey(), mlKemKeyPair.getPrivateKey());
            
            return new KemKeyPair(KemAlgorithm.HYBRID, publicKey, privateKey,
                combinedPublic, combinedPrivate);
        } finally {
            // Clean up individual key pairs
            x25519KeyPair.destroy();
            mlKemKeyPair.destroy();
        }
    }
    
    @Override
    public EncapsulationResult encapsulate(PublicKey recipientPublicKey) {
        Objects.requireNonNull(recipientPublicKey, "Recipient public key cannot be null");
        
        if (!(recipientPublicKey instanceof CompositePublicKey compositeKey)) {
            throw new EncapsulationException(
                "Expected CompositePublicKey for hybrid encapsulation, got: " 
                + recipientPublicKey.getClass().getName());
        }
        
        // Encapsulate using both algorithms
        EncapsulationResult x25519Result = null;
        EncapsulationResult mlKemResult = null;
        
        try {
            x25519Result = classicalProvider.encapsulate(compositeKey.getX25519Key());
            mlKemResult = mlKemProvider.encapsulate(compositeKey.getMlKemKey());
            
            // Combine shared secrets
            byte[] x25519Secret = x25519Result.getSharedSecret();
            byte[] mlKemSecret = mlKemResult.getSharedSecret();
            byte[] combinedSecret = combiner.combine(x25519Secret, mlKemSecret);
            
            // Combine ciphertexts
            byte[] x25519Ciphertext = x25519Result.getCiphertext();
            byte[] mlKemCiphertext = mlKemResult.getCiphertext();
            byte[] combinedCiphertext = encodeHybridCiphertext(x25519Ciphertext, mlKemCiphertext);
            
            // Clean up individual secrets
            SecureBytes.wipeAll(x25519Secret, mlKemSecret);
            
            return new EncapsulationResult(KemAlgorithm.HYBRID, combinedCiphertext, combinedSecret);
        } finally {
            if (x25519Result != null) x25519Result.destroy();
            if (mlKemResult != null) mlKemResult.destroy();
        }
    }
    
    @Override
    public EncapsulationResult encapsulate(byte[] encodedPublicKey) {
        Objects.requireNonNull(encodedPublicKey, "Encoded public key cannot be null");
        
        // Decode hybrid public key
        byte[][] parts = decodeHybridKey(encodedPublicKey);
        byte[] x25519EncodedKey = parts[0];
        byte[] mlKemEncodedKey = parts[1];
        
        // Encapsulate using both algorithms
        EncapsulationResult x25519Result = null;
        EncapsulationResult mlKemResult = null;
        
        try {
            x25519Result = classicalProvider.encapsulate(x25519EncodedKey);
            mlKemResult = mlKemProvider.encapsulate(mlKemEncodedKey);
            
            // Combine shared secrets
            byte[] x25519Secret = x25519Result.getSharedSecret();
            byte[] mlKemSecret = mlKemResult.getSharedSecret();
            byte[] combinedSecret = combiner.combine(x25519Secret, mlKemSecret);
            
            // Combine ciphertexts
            byte[] x25519Ciphertext = x25519Result.getCiphertext();
            byte[] mlKemCiphertext = mlKemResult.getCiphertext();
            byte[] combinedCiphertext = encodeHybridCiphertext(x25519Ciphertext, mlKemCiphertext);
            
            // Clean up
            SecureBytes.wipeAll(x25519Secret, mlKemSecret);
            
            return new EncapsulationResult(KemAlgorithm.HYBRID, combinedCiphertext, combinedSecret);
        } finally {
            if (x25519Result != null) x25519Result.destroy();
            if (mlKemResult != null) mlKemResult.destroy();
        }
    }
    
    @Override
    public byte[] decapsulate(KemKeyPair keyPair, byte[] ciphertext) {
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");
        
        PrivateKey privateKey = keyPair.getPrivateKey();
        
        if (!(privateKey instanceof CompositePrivateKey compositeKey)) {
            throw new EncapsulationException(
                "Expected CompositePrivateKey for hybrid decapsulation");
        }
        
        // Decode hybrid ciphertext
        byte[][] parts = decodeHybridCiphertext(ciphertext);
        byte[] x25519Ciphertext = parts[0];
        byte[] mlKemCiphertext = parts[1];
        
        // Create temporary key pairs for decapsulation (private key only)
        KemKeyPair x25519KeyPair = new KemKeyPair(
            KemAlgorithm.X25519, compositeKey.getX25519Key());
        KemKeyPair mlKemKeyPair = new KemKeyPair(
            KemAlgorithm.ML_KEM, compositeKey.getMlKemKey());
        
        try {
            // Decapsulate using both algorithms
            byte[] x25519Secret = classicalProvider.decapsulate(x25519KeyPair, x25519Ciphertext);
            byte[] mlKemSecret = mlKemProvider.decapsulate(mlKemKeyPair, mlKemCiphertext);
            
            // Combine shared secrets
            byte[] combinedSecret = combiner.combine(x25519Secret, mlKemSecret);
            
            // Clean up
            SecureBytes.wipeAll(x25519Secret, mlKemSecret);
            
            return combinedSecret;
        } finally {
            x25519KeyPair.destroy();
            mlKemKeyPair.destroy();
        }
    }
    
    @Override
    public int getCiphertextSize() {
        // 4 bytes for X25519 length + X25519 ciphertext + 4 bytes for ML-KEM length + ML-KEM ciphertext
        return 4 + classicalProvider.getCiphertextSize() + 4 + mlKemProvider.getCiphertextSize();
    }
    
    @Override
    public int getSharedSecretSize() {
        return SHARED_SECRET_SIZE;
    }
    
    /**
     * Encodes two key parts into a hybrid key format.
     * Format: len1 (4 bytes) || key1 || len2 (4 bytes) || key2
     */
    private byte[] encodeHybridKey(byte[] key1, byte[] key2) {
        byte[] result = new byte[4 + key1.length + 4 + key2.length];
        int offset = 0;
        
        writeInt(result, offset, key1.length);
        offset += 4;
        System.arraycopy(key1, 0, result, offset, key1.length);
        offset += key1.length;
        
        writeInt(result, offset, key2.length);
        offset += 4;
        System.arraycopy(key2, 0, result, offset, key2.length);
        
        return result;
    }
    
    /**
     * Decodes a hybrid key into its two component parts.
     */
    private byte[][] decodeHybridKey(byte[] hybridKey) {
        if (hybridKey.length < 8) {
            throw new EncapsulationException("Invalid hybrid key: too short");
        }
        
        int offset = 0;
        
        int len1 = readInt(hybridKey, offset);
        offset += 4;
        if (offset + len1 > hybridKey.length - 4) {
            throw new EncapsulationException("Invalid hybrid key: malformed");
        }
        byte[] key1 = SecureBytes.slice(hybridKey, offset, len1);
        offset += len1;
        
        int len2 = readInt(hybridKey, offset);
        offset += 4;
        if (offset + len2 > hybridKey.length) {
            throw new EncapsulationException("Invalid hybrid key: malformed");
        }
        byte[] key2 = SecureBytes.slice(hybridKey, offset, len2);
        
        return new byte[][] { key1, key2 };
    }
    
    /**
     * Alias for encodeHybridKey - same format for ciphertexts.
     */
    private byte[] encodeHybridCiphertext(byte[] ct1, byte[] ct2) {
        return encodeHybridKey(ct1, ct2);
    }
    
    /**
     * Alias for decodeHybridKey - same format for ciphertexts.
     */
    private byte[][] decodeHybridCiphertext(byte[] hybridCiphertext) {
        return decodeHybridKey(hybridCiphertext);
    }
    
    private static void writeInt(byte[] dest, int offset, int value) {
        dest[offset] = (byte) (value >>> 24);
        dest[offset + 1] = (byte) (value >>> 16);
        dest[offset + 2] = (byte) (value >>> 8);
        dest[offset + 3] = (byte) value;
    }
    
    private static int readInt(byte[] src, int offset) {
        return ((src[offset] & 0xFF) << 24) |
               ((src[offset + 1] & 0xFF) << 16) |
               ((src[offset + 2] & 0xFF) << 8) |
               (src[offset + 3] & 0xFF);
    }
    
    @Override
    public String toString() {
        return String.format("HybridKemProvider[X25519 + %s]", mlKemParameterSet.getParameterName());
    }
    
    /**
     * Composite public key holding both X25519 and ML-KEM public keys.
     */
    public static final class CompositePublicKey implements PublicKey {
        
        private static final long serialVersionUID = 1L;
        
        private final PublicKey x25519Key;
        private final PublicKey mlKemKey;
        
        public CompositePublicKey(PublicKey x25519Key, PublicKey mlKemKey) {
            this.x25519Key = x25519Key;
            this.mlKemKey = mlKemKey;
        }
        
        public PublicKey getX25519Key() {
            return x25519Key;
        }
        
        public PublicKey getMlKemKey() {
            return mlKemKey;
        }
        
        @Override
        public String getAlgorithm() {
            return "X25519-ML-KEM";
        }
        
        @Override
        public String getFormat() {
            return "HYBRID";
        }
        
        @Override
        public byte[] getEncoded() {
            // Note: For full encoding, use KemKeyPair.getEncodedPublicKey()
            byte[] x25519Encoded = x25519Key.getEncoded();
            byte[] mlKemEncoded = mlKemKey.getEncoded();
            return SecureBytes.concat(x25519Encoded, mlKemEncoded);
        }
    }
    
    /**
     * Composite private key holding both X25519 and ML-KEM private keys.
     */
    public static final class CompositePrivateKey implements PrivateKey {
        
        private static final long serialVersionUID = 1L;
        
        private final PrivateKey x25519Key;
        private final PrivateKey mlKemKey;
        
        public CompositePrivateKey(PrivateKey x25519Key, PrivateKey mlKemKey) {
            this.x25519Key = x25519Key;
            this.mlKemKey = mlKemKey;
        }
        
        public PrivateKey getX25519Key() {
            return x25519Key;
        }
        
        public PrivateKey getMlKemKey() {
            return mlKemKey;
        }
        
        @Override
        public String getAlgorithm() {
            return "X25519-ML-KEM";
        }
        
        @Override
        public String getFormat() {
            return "HYBRID";
        }
        
        @Override
        public byte[] getEncoded() {
            // Warning: This exposes private key material
            byte[] x25519Encoded = x25519Key.getEncoded();
            byte[] mlKemEncoded = mlKemKey.getEncoded();
            return SecureBytes.concat(x25519Encoded, mlKemEncoded);
        }
    }
}
