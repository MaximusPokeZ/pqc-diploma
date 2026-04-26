package io.mzaslav.pqc.signature;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import io.mzaslav.pqc.algorithm.ClassicalSigAlgorithm;
import io.mzaslav.pqc.algorithm.SignatureAlgorithm;
import io.mzaslav.pqc.exception.KeyGenerationException;
import io.mzaslav.pqc.exception.SignatureException;

/**
 * Classical (non post-quantum) digital signature provider.
 * <p>
 * Wraps the JCA signature engines for Ed25519, ECDSA P-256 and RSA-2048
 * behind the unified {@link SignatureProvider} contract. Used both standalone
 * (legacy interop) and as the classical half of {@link HybridSignatureProvider}.
 *
 * @author mzaslav
 * @since 1.0
 */
public final class ClassicalSignatureProvider implements SignatureProvider {

    private final ClassicalSigAlgorithm classicalAlgo;
    private final KeyPairGenerator keyPairGenerator;
    private final String signatureAlgorithmName;
    private final KeyFactory keyFactory;

    /**
     * Creates a provider for the requested classical signature algorithm.
     *
     * @param classicalAlgo the algorithm
     * @throws KeyGenerationException if the JCA provider cannot supply the algorithm
     */
    public ClassicalSignatureProvider(ClassicalSigAlgorithm classicalAlgo) {
        this.classicalAlgo = Objects.requireNonNull(classicalAlgo, "Algorithm cannot be null");
        try {
            switch (classicalAlgo) {
                case ED25519 -> {
                    this.keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
                    this.signatureAlgorithmName = "Ed25519";
                    this.keyFactory = KeyFactory.getInstance("Ed25519");
                }
                case ECDSA_P256 -> {
                    this.keyPairGenerator = KeyPairGenerator.getInstance("EC");
                    this.keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
                    this.signatureAlgorithmName = "SHA256withECDSA";
                    this.keyFactory = KeyFactory.getInstance("EC");
                }
                case RSA_2048 -> {
                    this.keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                    this.keyPairGenerator.initialize(2048);
                    this.signatureAlgorithmName = "SHA256withRSA";
                    this.keyFactory = KeyFactory.getInstance("RSA");
                }
                default -> throw new IllegalArgumentException("Unsupported signature algorithm");
            }
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new KeyGenerationException("Failed to initialize Classical Signature Provider", e);
        }
    }

    @Override
    public SignatureAlgorithm getAlgorithm() { return SignatureAlgorithm.CLASSICAL; }

    @Override
    public SignatureKeyPair generateKeyPair() {
        KeyPair kp = keyPairGenerator.generateKeyPair();
        return new SignatureKeyPair(SignatureAlgorithm.CLASSICAL, kp.getPublic(), kp.getPrivate());
    }

    @Override
    public byte[] sign(SignatureKeyPair keyPair, byte[] message) {
        return sign(keyPair.getPrivateKey(), message);
    }

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] message) {
        try {
            Signature sig = Signature.getInstance(signatureAlgorithmName);
            sig.initSign(privateKey);
            sig.update(message);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new SignatureException("Classical signing failed", e);
        }
    }

    @Override
    public byte[] sign(byte[] encodedPrivateKey, byte[] message) {
        try {
            PrivateKey privKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));
            return sign(privKey, message);
        } catch (InvalidKeySpecException e) {
            throw new SignatureException("Invalid encoded private key format", e);
        }
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] message, byte[] signatureBytes) {
        try {
            Signature sig = Signature.getInstance(signatureAlgorithmName);
            sig.initVerify(publicKey);
            sig.update(message);
            return sig.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    @Override
    public boolean verify(byte[] encodedPublicKey, byte[] message, byte[] signature) {
        try {
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
            return verify(pubKey, message, signature);
        } catch (InvalidKeySpecException e) {
            throw new SignatureException("Invalid encoded public key format", e);
        }
    }

    @Override
    public int getSignatureSize() {
        return switch (classicalAlgo) {
            case ED25519 -> 64;
            case ECDSA_P256 -> 72;
            case RSA_2048 -> 256;
        };
    }
}