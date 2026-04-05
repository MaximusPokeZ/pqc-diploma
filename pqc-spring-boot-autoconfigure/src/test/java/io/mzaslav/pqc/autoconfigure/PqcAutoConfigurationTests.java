package io.mzaslav.pqc.autoconfigure;

import io.mzaslav.pqc.algorithm.KemAlgorithm;
import io.mzaslav.pqc.algorithm.MlDsaParameterSet;
import io.mzaslav.pqc.algorithm.MlKemParameterSet;
import io.mzaslav.pqc.compression.CompressionAlgorithm;
import io.mzaslav.pqc.hybrid.EncryptedMessage;
import io.mzaslav.pqc.hybrid.HybridEncryptor;
import io.mzaslav.pqc.hybrid.HybridSigner;
import io.mzaslav.pqc.kem.KemKeyPair;
import io.mzaslav.pqc.signature.SignatureKeyPair;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PqcAutoConfigurationTests {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PqcAutoConfiguration.class));

    @Test
    void registersEncryptorAndSignerByDefault() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(HybridEncryptor.class);
            assertThat(context).hasSingleBean(HybridSigner.class);

            assertThat(context.getBean(HybridEncryptor.class).getAlgorithm()).isEqualTo(KemAlgorithm.HYBRID);
            assertThat(context.getBean(HybridSigner.class).getParameterSet()).isEqualTo(MlDsaParameterSet.ML_DSA_65);
        });
    }

    @Test
    void encryptionDisabledSkipsEncryptorBean() {
        contextRunner
                .withPropertyValues("pqc.encryption.enabled=false")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(HybridEncryptor.class);
                    assertThat(context).hasSingleBean(HybridSigner.class);
                });
    }

    @Test
    void signatureDisabledSkipsSignerBean() {
        contextRunner
                .withPropertyValues("pqc.signature.enabled=false")
                .run(context -> {
                    assertThat(context).hasSingleBean(HybridEncryptor.class);
                    assertThat(context).doesNotHaveBean(HybridSigner.class);
                });
    }

    @Test
    void pqcOnlyModeUsesPqcAlgorithm() {
        contextRunner
                .withPropertyValues("pqc.encryption.mode=PQC_ONLY")
                .run(context -> {
                    HybridEncryptor enc = context.getBean(HybridEncryptor.class);
                    assertThat(enc.getAlgorithm()).isEqualTo(KemAlgorithm.ML_KEM);
                    assertThat(enc.getMlKemParameterSet()).isEqualTo(MlKemParameterSet.ML_KEM_768);
                });
    }

    @Test
    void classicalOnlyModeUsesClassicalKem() {
        contextRunner
                .withPropertyValues("pqc.encryption.mode=CLASSICAL_ONLY")
                .run(context -> {
                    HybridEncryptor enc = context.getBean(HybridEncryptor.class);
                    assertThat(enc.getAlgorithm()).isEqualTo(KemAlgorithm.X25519);
                    assertThat(enc.getMlKemParameterSet()).isNull();
                });
    }

    @Test
    void bindsPqcAlgorithmFromProperties() {
        contextRunner
                .withPropertyValues(
                        "pqc.encryption.mode=PQC_ONLY",
                        "pqc.encryption.pqc-algorithm=ML_KEM_512")
                .run(context -> assertThat(context.getBean(HybridEncryptor.class).getMlKemParameterSet())
                        .isEqualTo(MlKemParameterSet.ML_KEM_512));
    }

    @Test
    void bindsSignaturePqcAlgorithmFromProperties() {
        contextRunner
                .withPropertyValues("pqc.signature.pqc-algorithm=ML_DSA_44")
                .run(context -> assertThat(context.getBean(HybridSigner.class).getParameterSet())
                        .isEqualTo(MlDsaParameterSet.ML_DSA_44));
    }

    @Test
    void compressionRoundTripWithGzip() {
        byte[] plaintext = new byte[16_000];
        Arrays.fill(plaintext, (byte) 7);

        contextRunner
                .withPropertyValues(
                        "pqc.encryption.compression.enabled=true",
                        "pqc.encryption.compression.algorithm=GZIP")
                .run(context -> {
                    HybridEncryptor encryptor = context.getBean(HybridEncryptor.class);

                    try (KemKeyPair kp = encryptor.generateKeyPair()) {
                        EncryptedMessage msg = encryptor.encrypt(kp.getEncodedPublicKey(), plaintext);

                        assertThat(msg.getCompressionAlgorithm()).isEqualTo(CompressionAlgorithm.GZIP);

                        byte[] out = encryptor.decrypt(kp, msg);
                        assertThat(out).isEqualTo(plaintext);
                    }
                });
    }

    @Test
    void signerSignAndVerifyRoundTrip() {
        contextRunner.run(context -> {
            HybridSigner signer = context.getBean(HybridSigner.class);

            try (SignatureKeyPair kp = signer.generateKeyPair()) {
                byte[] message = "payload".getBytes();
                byte[] sig = signer.sign(kp, message);
                assertThat(signer.verify(kp, message, sig)).isTrue();
            }
        });
    }

    @Test
    void rejectsCompressionEnabledWithNoneAlgorithm() {
        contextRunner
                .withPropertyValues(
                        "pqc.encryption.compression.enabled=true",
                        "pqc.encryption.compression.algorithm=NONE")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("Compression is enabled, but algorithm is set to NONE");
                });
    }

    @Test
    void loadsConfigurationFromYamlFile() {
        contextRunner
                .withInitializer(context -> loadYamlIntoContext(context, "pqc-test.yml"))
                .run(context -> {
                    assertThat(context).hasSingleBean(HybridEncryptor.class);
                    assertThat(context).hasSingleBean(HybridSigner.class);

                    HybridEncryptor encryptor = context.getBean(HybridEncryptor.class);
                    HybridSigner signer = context.getBean(HybridSigner.class);

                    assertThat(encryptor.getAlgorithm()).isEqualTo(KemAlgorithm.ML_KEM);
                    assertThat(encryptor.getMlKemParameterSet()).isEqualTo(MlKemParameterSet.ML_KEM_512);
                    assertThat(signer.getParameterSet()).isEqualTo(MlDsaParameterSet.ML_DSA_44);

                    byte[] plaintext = new byte[8_000];
                    Arrays.fill(plaintext, (byte) 3);

                    try (KemKeyPair kp = encryptor.generateKeyPair()) {
                        EncryptedMessage msg = encryptor.encrypt(kp.getEncodedPublicKey(), plaintext);

                        assertThat(msg.getCompressionAlgorithm()).isEqualTo(CompressionAlgorithm.ZSTD);
                        assertThat(encryptor.decrypt(kp, msg)).isEqualTo(plaintext);
                    }
                });
    }

    private static void loadYamlIntoContext(org.springframework.context.ConfigurableApplicationContext context,
                                            String classpathResource) {
        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        Resource resource = new ClassPathResource(classpathResource);
        List<PropertySource<?>> sources;
        try {
            sources = loader.load("yaml-test", resource);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        for (int i = sources.size() - 1; i >= 0; i--) {
            context.getEnvironment().getPropertySources().addFirst(sources.get(i));
        }
    }
}
