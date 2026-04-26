package io.mzaslav.pqc.signature;

import io.mzaslav.pqc.algorithm.MlDsaParameterSet;
import io.mzaslav.pqc.algorithm.SignatureAlgorithm;
import io.mzaslav.pqc.util.SecureBytes;

/**
 * Hybrid digital signature provider combining a classical scheme
 * (Ed25519, ECDSA P-256 or RSA-2048) with ML-DSA (FIPS 204).
 * <p>
 * Both signatures must verify for the hybrid signature to be accepted; the
 * scheme is therefore secure as long as either component remains unbroken.
 * <p>
 * Wire format for keys and signatures: {@code len1 || data1 || len2 || data2}
 * where lengths are 4-byte big-endian integers.
 *
 * @author mzaslav
 * @since 1.0
 */
public final class HybridSignatureProvider implements SignatureProvider {

    private final ClassicalSignatureProvider classicalProvider;
    private final MlDsaProvider mlDsaProvider;

    /**
     * Creates a new hybrid signature provider.
     *
     * @param classicalProvider  the classical signature provider
     * @param mlDsaParameterSet  the ML-DSA parameter set
     */
    public HybridSignatureProvider(ClassicalSignatureProvider classicalProvider, MlDsaParameterSet mlDsaParameterSet) {
        this.classicalProvider = classicalProvider;
        this.mlDsaProvider = new MlDsaProvider(mlDsaParameterSet);
    }

    @Override
    public SignatureAlgorithm getAlgorithm() { return SignatureAlgorithm.HYBRID; }

    @Override
    public SignatureKeyPair generateKeyPair() {
        SignatureKeyPair classKp = classicalProvider.generateKeyPair();
        SignatureKeyPair pqcKp = mlDsaProvider.generateKeyPair();

        try {
            byte[] combinedPub = encodeHybridData(classKp.getEncodedPublicKey(), pqcKp.getEncodedPublicKey());
            byte[] combinedPriv = encodeHybridData(classKp.getEncodedPrivateKey(), pqcKp.getEncodedPrivateKey());

            // For hybrid we operate on encoded byte arrays; JCA Key objects are placeholders.
            return new SignatureKeyPair(SignatureAlgorithm.HYBRID,
                    classKp.getPublicKey(), classKp.getPrivateKey(),
                    combinedPub, combinedPriv);
        } finally {
            classKp.destroy();
            pqcKp.destroy();
        }
    }

    @Override
    public byte[] sign(byte[] encodedPrivateKey, byte[] message) {
        byte[][] keys = decodeHybridData(encodedPrivateKey);
        byte[] classSig = classicalProvider.sign(keys[0], message);
        byte[] pqcSig = mlDsaProvider.sign(keys[1], message);
        return encodeHybridData(classSig, pqcSig);
    }

    @Override
    public byte[] sign(SignatureKeyPair keyPair, byte[] message) {
        return sign(keyPair.getEncodedPrivateKey(), message);
    }

    @Override
    public byte[] sign(java.security.PrivateKey privateKey, byte[] message) {
        throw new UnsupportedOperationException("Hybrid signatures require a composite byte array, not a single JCA PrivateKey");
    }

    @Override
    public boolean verify(byte[] encodedPublicKey, byte[] message, byte[] signature) {
        try {
            byte[][] pubKeys = decodeHybridData(encodedPublicKey);
            byte[][] sigs = decodeHybridData(signature);

            boolean classValid = classicalProvider.verify(pubKeys[0], message, sigs[0]);
            boolean pqcValid = mlDsaProvider.verify(pubKeys[1], message, sigs[1]);

            return classValid && pqcValid;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean verify(java.security.PublicKey publicKey, byte[] message, byte[] signature) {
        throw new UnsupportedOperationException("Hybrid verification requires a composite byte array");
    }

    @Override
    public int getSignatureSize() {
        // 8 = two 4-byte length prefixes
        return 8 + classicalProvider.getSignatureSize() + mlDsaProvider.getSignatureSize();
    }

    private byte[] encodeHybridData(byte[] d1, byte[] d2) {
        byte[] res = new byte[8 + d1.length + d2.length];
        writeInt(res, 0, d1.length);
        System.arraycopy(d1, 0, res, 4, d1.length);
        writeInt(res, 4 + d1.length, d2.length);
        System.arraycopy(d2, 0, res, 8 + d1.length, d2.length);
        return res;
    }

    private byte[][] decodeHybridData(byte[] data) {
        int len1 = readInt(data, 0);
        byte[] d1 = SecureBytes.slice(data, 4, len1);
        int len2 = readInt(data, 4 + len1);
        byte[] d2 = SecureBytes.slice(data, 8 + len1, len2);
        return new byte[][] { d1, d2 };
    }

    private static void writeInt(byte[] dest, int offset, int value) {
        dest[offset] = (byte) (value >>> 24); dest[offset+1] = (byte) (value >>> 16);
        dest[offset+2] = (byte) (value >>> 8); dest[offset+3] = (byte) value;
    }

    private static int readInt(byte[] src, int offset) {
        return ((src[offset] & 0xFF) << 24) | ((src[offset+1] & 0xFF) << 16) |
                ((src[offset+2] & 0xFF) << 8) | (src[offset+3] & 0xFF);
    }
}