package io.mzaslav.pqc.autoconfigure;

import io.mzaslav.pqc.algorithm.MlDsaParameterSet;
import io.mzaslav.pqc.algorithm.MlKemParameterSet;
import io.mzaslav.pqc.algorithm.ClassicalKemAlgorithm;
import io.mzaslav.pqc.algorithm.ClassicalSigAlgorithm;
import io.mzaslav.pqc.algorithm.CryptoMode;
import io.mzaslav.pqc.compression.CompressionAlgorithm;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Type-safe binding for {@code pqc.*} configuration in
 * {@code application.yml} / {@code application.properties}.
 * <p>
 * Validation rules ensure that the algorithm fields required by the chosen
 * {@link CryptoMode} are set, and that compression is consistently configured.
 * <p>
 * Example:
 * <pre>{@code
 * pqc:
 *   encryption:
 *     mode: HYBRID
 *     pqc-algorithm: ML_KEM_768
 *     classical-algorithm: X25519
 *     compression:
 *       enabled: true
 *       algorithm: ZSTD
 *   signature:
 *     mode: HYBRID
 *     pqc-algorithm: ML_DSA_65
 *     classical-algorithm: ED25519
 * }</pre>
 *
 * @author mzaslav
 * @since 1.0
 */
@ConfigurationProperties(prefix = "pqc")
@Validated
public class PqcProperties {

    @Valid
    private final Encryption encryption = new Encryption();

    @Valid
    private final Signature signature = new Signature();

    public Encryption getEncryption() { return encryption; }
    public Signature getSignature() { return signature; }

    /**
     * Encryption settings (KEM choice, mode, optional compression).
     */
    public static class Encryption {
        private boolean enabled = true;

        @NotNull
        private CryptoMode mode = CryptoMode.HYBRID;

        private MlKemParameterSet pqcAlgorithm = MlKemParameterSet.ML_KEM_768;

        private ClassicalKemAlgorithm classicalAlgorithm = ClassicalKemAlgorithm.X25519;

        @Valid
        @NotNull
        private final Compression compression = new Compression();

        @AssertTrue(message = "pqc.encryption.pqc-algorithm must be set for HYBRID or PQC_ONLY modes")
        public boolean isPqcAlgorithmSetIfRequired() {
            if (mode == CryptoMode.HYBRID || mode == CryptoMode.PQC_ONLY) {
                return pqcAlgorithm != null;
            }
            return true;
        }

        @AssertTrue(message = "pqc.encryption.classical-algorithm must be set for HYBRID or CLASSICAL_ONLY modes")
        public boolean isClassicalAlgorithmSetIfRequired() {
            if (mode == CryptoMode.HYBRID || mode == CryptoMode.CLASSICAL_ONLY) {
                return classicalAlgorithm != null;
            }
            return true;
        }

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public CryptoMode getMode() { return mode; }
        public void setMode(CryptoMode mode) { this.mode = mode; }
        public MlKemParameterSet getPqcAlgorithm() { return pqcAlgorithm; }
        public void setPqcAlgorithm(MlKemParameterSet pqcAlgorithm) { this.pqcAlgorithm = pqcAlgorithm; }
        public ClassicalKemAlgorithm getClassicalAlgorithm() { return classicalAlgorithm; }
        public void setClassicalAlgorithm(ClassicalKemAlgorithm classicalAlgorithm) { this.classicalAlgorithm = classicalAlgorithm; }
        public Compression getCompression() { return compression; }
    }

    /**
     * Optional compression applied to plaintext before encryption.
     */
    public static class Compression {
        private boolean enabled = false;

        @NotNull
        private CompressionAlgorithm algorithm = CompressionAlgorithm.NONE;

        @AssertTrue(message = "Compression is enabled, but algorithm is set to NONE")
        public boolean isValid() {
            return !enabled || algorithm != CompressionAlgorithm.NONE;
        }

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public CompressionAlgorithm getAlgorithm() { return algorithm; }
        public void setAlgorithm(CompressionAlgorithm algorithm) { this.algorithm = algorithm; }
    }

    /**
     * Digital signature settings (signing algorithm choice and mode).
     */
    public static class Signature {
        private boolean enabled = true;

        @NotNull
        private CryptoMode mode = CryptoMode.HYBRID;

        private MlDsaParameterSet pqcAlgorithm = MlDsaParameterSet.ML_DSA_65;

        private ClassicalSigAlgorithm classicalAlgorithm = ClassicalSigAlgorithm.ED25519;

        @AssertTrue(message = "pqc.signature.pqc-algorithm must be set for HYBRID or PQC_ONLY modes")
        public boolean isPqcAlgorithmSetIfRequired() {
            if (mode == CryptoMode.HYBRID || mode == CryptoMode.PQC_ONLY) {
                return pqcAlgorithm != null;
            }
            return true;
        }

        @AssertTrue(message = "pqc.signature.classical-algorithm must be set for HYBRID or CLASSICAL_ONLY modes")
        public boolean isClassicalAlgorithmSetIfRequired() {
            if (mode == CryptoMode.HYBRID || mode == CryptoMode.CLASSICAL_ONLY) {
                return classicalAlgorithm != null;
            }
            return true;
        }

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public CryptoMode getMode() { return mode; }
        public void setMode(CryptoMode mode) { this.mode = mode; }
        public MlDsaParameterSet getPqcAlgorithm() { return pqcAlgorithm; }
        public void setPqcAlgorithm(MlDsaParameterSet pqcAlgorithm) { this.pqcAlgorithm = pqcAlgorithm; }
        public ClassicalSigAlgorithm getClassicalAlgorithm() { return classicalAlgorithm; }
        public void setClassicalAlgorithm(ClassicalSigAlgorithm classicalAlgorithm) { this.classicalAlgorithm = classicalAlgorithm; }
    }
}
