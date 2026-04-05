package io.mzaslav.pqc.kem;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import javax.crypto.KeyAgreement;

import io.mzaslav.pqc.algorithm.KemAlgorithm;
import io.mzaslav.pqc.exception.EncapsulationException;
import io.mzaslav.pqc.exception.KeyGenerationException;

public final class Secp256r1Provider implements KemProvider {

    private static final String KEY_FACTORY_ALGO = "EC";
    private static final String KEY_AGREEMENT_ALGO = "ECDH";
    private static final String CURVE_NAME = "secp256r1";
    private static final int CIPHERTEXT_SIZE = 91;
    private static final int SHARED_SECRET_SIZE = 32;

    private final KeyPairGenerator keyPairGenerator;
    private final KeyFactory keyFactory;

    public Secp256r1Provider() {
        try {
            this.keyPairGenerator = KeyPairGenerator.getInstance(KEY_FACTORY_ALGO);
            this.keyPairGenerator.initialize(new ECGenParameterSpec(CURVE_NAME));
            this.keyFactory = KeyFactory.getInstance(KEY_FACTORY_ALGO);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new KeyGenerationException("SECP256R1 algorithm not available", e);
        }
    }

    @Override
    public KemAlgorithm getAlgorithm() {
        return KemAlgorithm.SECP256R1;
    }

    @Override
    public synchronized KemKeyPair generateKeyPair() {
        try {
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return new KemKeyPair(KemAlgorithm.SECP256R1, keyPair.getPublic(), keyPair.getPrivate());
        } catch (Exception e) {
            throw new KeyGenerationException("Failed to generate SECP256R1 key pair", e);
        }
    }

    @Override
    public EncapsulationResult encapsulate(PublicKey recipientPublicKey) {
        Objects.requireNonNull(recipientPublicKey, "Recipient public key cannot be null");
        try {
            KeyPair ephemeralKeyPair = keyPairGenerator.generateKeyPair();

            KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGO);
            keyAgreement.init(ephemeralKeyPair.getPrivate());
            keyAgreement.doPhase(recipientPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            byte[] ciphertext = ephemeralKeyPair.getPublic().getEncoded();
            return new EncapsulationResult(KemAlgorithm.SECP256R1, ciphertext, sharedSecret);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new EncapsulationException("SECP256R1 encapsulation failed", e);
        }
    }

    @Override
    public EncapsulationResult encapsulate(byte[] encodedPublicKey) {
        Objects.requireNonNull(encodedPublicKey, "Encoded public key cannot be null");
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedPublicKey);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            return encapsulate(publicKey);
        } catch (InvalidKeySpecException e) {
            throw new EncapsulationException("Invalid encoded SECP256R1 public key format", e);
        }
    }

    @Override
    public byte[] decapsulate(KemKeyPair keyPair, byte[] ciphertext) {
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(ciphertext);
            PublicKey ephemeralPublicKey = keyFactory.generatePublic(keySpec);

            KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGO);
            keyAgreement.init(keyPair.getPrivateKey());
            keyAgreement.doPhase(ephemeralPublicKey, true);

            return keyAgreement.generateSecret();
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
            throw new EncapsulationException("SECP256R1 decapsulation failed", e);
        }
    }

    @Override
    public int getCiphertextSize() {
        return CIPHERTEXT_SIZE;
    }

    @Override
    public int getSharedSecretSize() {
        return SHARED_SECRET_SIZE;
    }

    @Override
    public String toString() {
        return "Secp256r1Provider";
    }
}