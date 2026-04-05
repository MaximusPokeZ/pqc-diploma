package io.mzaslav.pqc.signature;

import io.mzaslav.pqc.algorithm.MlDsaParameterSet;
import io.mzaslav.pqc.algorithm.SignatureAlgorithm;
import io.mzaslav.pqc.util.SecureBytes;

public final class HybridSignatureProvider implements SignatureProvider {

    private final ClassicalSignatureProvider classicalProvider;
    private final MlDsaProvider mlDsaProvider;

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

            return new SignatureKeyPair(SignatureAlgorithm.HYBRID,
                    classKp.getPublicKey(), classKp.getPrivateKey(), // JCA объекты здесь оставляем пустышками (для гибрида мы юзаем байты)
                    combinedPub, combinedPriv);
        } finally {
            classKp.destroy();
            pqcKp.destroy();
        }
    }

    @Override
    public byte[] sign(byte[] encodedPrivateKey, byte[] message) {
        // 1. Декодируем гибридный ключ на 2 части
        byte[][] keys = decodeHybridData(encodedPrivateKey);

        // 2. Подписываем классическим алгоритмом (Ed25519)
        byte[] classSig = classicalProvider.sign(keys[0], message);

        // 3. Подписываем постквантовым алгоритмом (ML-DSA)
        byte[] pqcSig = mlDsaProvider.sign(keys[1], message);

        // 4. Склеиваем подписи в одну
        return encodeHybridData(classSig, pqcSig);
    }

    @Override
    public byte[] sign(SignatureKeyPair keyPair, byte[] message) {
        // Делегируем подписание массиву байт!
        return sign(keyPair.getEncodedPrivateKey(), message);
    }

    @Override
    public byte[] sign(java.security.PrivateKey privateKey, byte[] message) {
        throw new UnsupportedOperationException("Hybrid signatures require a composite byte array, not a single JCA PrivateKey");
    }

    @Override
    public boolean verify(byte[] encodedPublicKey, byte[] message, byte[] signature) {
        try {
            // Декодируем два публичных ключа и две подписи
            byte[][] pubKeys = decodeHybridData(encodedPublicKey);
            byte[][] sigs = decodeHybridData(signature);

            // Проверяем классику
            boolean classValid = classicalProvider.verify(pubKeys[0], message, sigs[0]);

            // Проверяем постквант
            boolean pqcValid = mlDsaProvider.verify(pubKeys[1], message, sigs[1]);

            // Для успеха должны совпасть ОБЕ подписи!
            return classValid && pqcValid;
        } catch (Exception e) {
            return false; // Защита от OutOfBoundsEx при кривых данных
        }
    }

    @Override
    public boolean verify(java.security.PublicKey publicKey, byte[] message, byte[] signature) {
        throw new UnsupportedOperationException("Hybrid verification requires a composite byte array");
    }

    @Override
    public int getSignatureSize() {
        // Конкатенация + 8 байт (два инта длины)
        return 8 + classicalProvider.getSignatureSize() + mlDsaProvider.getSignatureSize();
    }

    // --- Внутренние утилиты для объединения массивов ---
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