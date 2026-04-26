package io.mzaslav.pqc.autoconfigure;

import io.mzaslav.pqc.algorithm.CryptoMode;
import io.mzaslav.pqc.compression.DataCompressor;
import io.mzaslav.pqc.hybrid.HybridEncryptor;
import io.mzaslav.pqc.hybrid.HybridSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Spring Boot auto-configuration for the PQC hybrid cryptography library.
 * <p>
 * Reads {@code pqc.*} properties via {@link PqcProperties} and exposes
 * {@link HybridEncryptor} and {@link HybridSigner} beans configured for the
 * requested mode (HYBRID, PQC_ONLY or CLASSICAL_ONLY). Beans are only
 * registered when the corresponding {@code pqc.encryption.enabled} /
 * {@code pqc.signature.enabled} property is {@code true} (default) and no
 * user-provided bean of the same type already exists.
 * <p>
 * Activated automatically through {@code spring.factories} /
 * {@code AutoConfiguration.imports}; consumers normally pull this in
 * transitively through the {@code pqc-hybrid-spring-boot-starter} module.
 *
 * @author mzaslav
 * @since 1.0
 */
@AutoConfiguration
@ConditionalOnClass({HybridEncryptor.class, HybridSigner.class})
@EnableConfigurationProperties(PqcProperties.class)
public class PqcAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(PqcAutoConfiguration.class);

    /**
     * Builds and configures a {@link HybridEncryptor} bean from the bound
     * {@code pqc.encryption.*} properties, attaching a {@link DataCompressor}
     * when compression is enabled.
     *
     * @param properties resolved PQC configuration
     * @return the configured encryptor
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "pqc.encryption", name = "enabled", havingValue = "true", matchIfMissing = true)
    public HybridEncryptor hybridEncryptor(PqcProperties properties) {
        PqcProperties.Encryption encCfg = properties.getEncryption();
        HybridEncryptor encryptor = buildEncryptor(encCfg);

        PqcProperties.Compression compCfg = encCfg.getCompression();
        if (compCfg.isEnabled()) {
            DataCompressor compressor = PqcCompressors.create(compCfg.getAlgorithm());
            encryptor.setCompressor(compressor);
            log.info("[PQC Starter] Encryption Compression enabled: {}", compCfg.getAlgorithm());
        }

        log.info("[PQC Starter] Encryptor built | Mode: {} | PQC: {} | Classical: {}",
                encCfg.getMode(),
                encCfg.getMode() != CryptoMode.CLASSICAL_ONLY ? encCfg.getPqcAlgorithm() : "N/A",
                encCfg.getMode() != CryptoMode.PQC_ONLY ? encCfg.getClassicalAlgorithm() : "N/A");

        return encryptor;
    }

    /**
     * Builds and configures a {@link HybridSigner} bean from the bound
     * {@code pqc.signature.*} properties.
     *
     * @param properties resolved PQC configuration
     * @return the configured signer
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "pqc.signature", name = "enabled", havingValue = "true", matchIfMissing = true)
    public HybridSigner hybridSigner(PqcProperties properties) {
        PqcProperties.Signature sigCfg = properties.getSignature();

        HybridSigner signer = buildSigner(sigCfg);

        log.info("[PQC Starter] Signer built | Mode: {} | PQC: {} | Classical: {}",
                sigCfg.getMode(),
                sigCfg.getMode() != CryptoMode.CLASSICAL_ONLY ? sigCfg.getPqcAlgorithm() : "N/A",
                sigCfg.getMode() != CryptoMode.PQC_ONLY ? sigCfg.getClassicalAlgorithm() : "N/A");

        return signer;
    }

    private static HybridSigner buildSigner(PqcProperties.Signature cfg) {
        return switch (cfg.getMode()) {
            case HYBRID -> HybridSigner.create(cfg.getClassicalAlgorithm(), cfg.getPqcAlgorithm());
            case PQC_ONLY -> HybridSigner.createPqcOnly(cfg.getPqcAlgorithm());
            case CLASSICAL_ONLY -> HybridSigner.createClassicalOnly(cfg.getClassicalAlgorithm());
        };
    }

    private static HybridEncryptor buildEncryptor(PqcProperties.Encryption cfg) {
        return switch (cfg.getMode()) {
            case HYBRID -> HybridEncryptor.create(cfg.getClassicalAlgorithm(), cfg.getPqcAlgorithm());
            case PQC_ONLY -> HybridEncryptor.createPqcOnly(cfg.getPqcAlgorithm());
            case CLASSICAL_ONLY -> HybridEncryptor.createClassicalOnly(cfg.getClassicalAlgorithm());
        };
    }

}
